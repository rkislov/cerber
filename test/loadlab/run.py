# SPDX-License-Identifier: Apache-2.0
"""Isolated live-packet load/recovery lab. Run only through launch.py (network=none)."""
import datetime, hashlib, http.client, http.server, json, os, pathlib
import socket, sqlite3, struct, subprocess, threading, time, traceback

ROOT = pathlib.Path('/lab')
OUT = ROOT/'evidence'
SID = 9900001
PROCS = {}
SENT = {}
EVE = {}
NORMAL = {}
DETECTIONS = {}
SAMPLES = []
PHASE = 'startup'
STOP = threading.Event()
ERRORS = []
PROXY = {'blocked': False, 'drop_ack': 0, 'acks_dropped': 0, 'rejected': 0}
RESULT = {'schema': 1, 'phases': [], 'isolation': {'network': 'none', 'smtp': 'absent', 'active_response': 'absent', 'production_access': False}}

def save(name, value):
    (OUT/name).write_text(json.dumps(value, ensure_ascii=False, indent=2)+'\n')

def mark(message):
    print(datetime.datetime.now(datetime.timezone.utc).isoformat(), message, flush=True)

def start(name, args):
    log = (OUT/(name+'.log')).open('ab')
    p = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT)
    log.close(); PROCS[name] = p
    return p

def stop(name, crash=False):
    p = PROCS[name]
    if p.poll() is None:
        p.kill() if crash else p.terminate()
        p.wait(timeout=30)

def server():
    return start('siem', ['cerber', '-db', '/lab/state/control.db', 'siem', 'serve', '-admin', '-listen', '127.0.0.1:18790', '-events-db', '/lab/state/events.db'])

def sensor():
    return start('sensor', ['cerber-sensor', '-config', '/lab/state/sensor.json'])

def engine():
    return start('suricata', ['suricata', '--runmode', 'single', '--init-errors-fatal', '-c', '/lab/state/suricata.yaml', '--af-packet=cerber-span', '-F', '/lab/filter.bpf', '-l', '/lab/eve'])

def wait(fn, label, timeout=360):
    end = time.monotonic()+timeout
    while time.monotonic() < end:
        if ERRORS: raise RuntimeError(ERRORS)
        value = fn()
        if value: return value
        time.sleep(.25)
    raise AssertionError('Timeout: '+label)

def ready():
    try:
        c = http.client.HTTPConnection('127.0.0.1',18790,timeout=2)
        c.request('GET','/admin/'); r=c.getresponse(); r.read(); c.close()
        return r.status == 200
    except OSError: return False

class Proxy(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_POST(self):
        data = self.rfile.read(int(self.headers.get('Content-Length','0')))
        if PROXY['blocked']:
            PROXY['rejected'] += 1
            self.send_error(503, 'isolated fault injection'); return
        c = http.client.HTTPConnection('127.0.0.1',18790,timeout=15)
        try:
            c.request('POST',self.path,data,{k:v for k,v in self.headers.items() if k.lower() not in ('host','connection')})
            r=c.getresponse(); body=r.read()
            if self.path.endswith('/events') and r.status < 300 and PROXY['drop_ack']:
                PROXY['drop_ack'] -= 1; PROXY['acks_dropped'] += 1
                self.connection.shutdown(socket.SHUT_RDWR); self.connection.close(); return
            self.send_response(r.status); self.send_header('Content-Type','application/json'); self.end_headers(); self.wfile.write(body)
        except (OSError,http.client.HTTPException):
            try:self.send_error(502,'isolated upstream unavailable')
            except OSError:pass
        finally:c.close()

def connect(name):
    p=ROOT/'state'/name
    if not p.exists():return None
    return sqlite3.connect('file:'+str(p)+'?mode=ro',uri=True,timeout=.15)

def sample():
    ticks=os.sysconf('SC_CLK_TCK'); previous={}; cursors={'normalized_events':0,'detections':0}; eve_pos=0; eve_inode=None
    while not STOP.is_set():
        at=time.time(); row={'at':at,'phase':PHASE,'processes':{}}
        for name,p in list(PROCS.items()):
            try:
                fields=pathlib.Path('/proc/'+str(p.pid)+'/stat').read_text().split(') ',1)[1].split()
                cpu=(int(fields[11])+int(fields[12]))/ticks
                rss=int(fields[21])*os.sysconf('SC_PAGE_SIZE')
                old=previous.get(name); percent=100*(cpu-old[1])/(at-old[2]) if old and old[0]==p.pid else None
                previous[name]=(p.pid,cpu,at)
                row['processes'][name]={'pid':p.pid,'cpu_percent':percent,'rss_bytes':rss}
            except (OSError,IndexError):pass
        try:
            path=ROOT/'eve/eve.json'
            if path.exists():
                st=path.stat()
                if st.st_ino != eve_inode or st.st_size < eve_pos:eve_pos=0;eve_inode=st.st_ino
                with path.open() as f:
                    f.seek(eve_pos)
                    while True:
                        line=f.readline()
                        if not line.endswith('\n'):break
                        eve_pos=f.tell();v=json.loads(line)
                        EVE[(v['event_type'],str(v.get('flow_id')),v.get('alert',{}).get('signature_id'))]=(at,v)
            db=connect('events.db')
            if db:
                for table,target in [('normalized_events',NORMAL),('detections',DETECTIONS)]:
                    rows=db.execute('SELECT sequence,id,payload FROM '+table+' WHERE sequence>? ORDER BY sequence',(cursors[table],)).fetchall()
                    observed=time.time()
                    for seq,key,payload in rows:
                        target[key]=(observed,json.loads(payload));cursors[table]=seq
                row['raw']=db.execute('SELECT count(*) FROM raw_events').fetchone()[0]
                row['normalized']=len(NORMAL);row['detections']=len(DETECTIONS)
                positions=dict(db.execute('SELECT name,position FROM consumer_cursors'))
                maximum=db.execute('SELECT coalesce(max(sequence),0) FROM raw_events').fetchone()[0]
                row['pending_normalization']=maximum-positions['normalizer/1']
                row['pending_correlation']=cursors['normalized_events']-positions['correlator/1']
                db.close()
            q=connect('queue.db')
            if q:
                row['queue_batches'],row['queue_bytes'],row['queue_records']=q.execute("SELECT count(*),coalesce(sum(length(cast(payload AS BLOB))),0),coalesce(sum(json_array_length(payload,'$.records')),0) FROM event_spool").fetchone();q.close()
        except sqlite3.OperationalError:
            row['sample_busy']=True
        except Exception as e:
            ERRORS.append(str(e));return
        row['eve_records']=len(EVE)
        row['source_backlog_records']=max(0,len(EVE)-row.get('raw',0)-row.get('queue_records',0))
        row['eve_bytes']=(ROOT/'eve/eve.json').stat().st_size if (ROOT/'eve/eve.json').exists() else 0
        SAMPLES.append(row)
        with (OUT/'samples.jsonl').open('a') as f:f.write(json.dumps(row)+'\n')
        STOP.wait(.5)

def checksum(data):
    if len(data)%2:data+=b'\0'
    s=sum(struct.unpack('!'+str(len(data)//2)+'H',data));s=(s>>16)+(s&65535);s+=(s>>16)
    return (~s)&65535

def packet(number):
    # Unique source IP prevents normal 60-second correlation suppression from
    # being mistaken for loss. All packets remain inside the network namespace.
    ip=socket.inet_ntoa(struct.pack('!I',0x0a400000+number))
    payload=b'CERBER_LOADLAB_'+str(number).encode()
    udp=struct.pack('!HHHH',40000,49000,8+len(payload),0)+payload
    hdr=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(udp),number%65536,0,64,17,0,socket.inet_aton(ip),socket.inet_aton('192.0.2.20'))
    hdr=hdr[:10]+struct.pack('!H',checksum(hdr))+hdr[12:]
    return ip,bytes.fromhex('0200000000020200000000010800')+hdr+udp

def send(rate, seconds):
    sock=socket.socket(socket.AF_PACKET,socket.SOCK_RAW);sock.bind(('cerber-tap',0))
    begin=time.monotonic();count=int(rate*seconds);ids=[]
    with (OUT/'traffic.pcap').open('ab') as pcap:
        for i in range(count):
            delay=begin+i/rate-time.monotonic()
            if delay>0:time.sleep(delay)
            number=len(SENT)+1;ip,frame=packet(number);at=time.time()
            assert sock.send(frame)==len(frame)
            SENT[ip]={'at':at,'phase':PHASE,'number':number};ids.append(ip)
            sec=int(at);pcap.write(struct.pack('<IIII',sec,int((at-sec)*1e6),len(frame),len(frame))+frame)
    elapsed=time.monotonic()-begin;sock.close()
    return ids,elapsed

def done(ids):
    wanted=set(ids)
    alerts={v['source_ip'] for _,v in list(NORMAL.values()) if v.get('code')==str(SID)}
    dets={v['source_ip'] for _,v in list(DETECTIONS.values()) if v.get('rule')=='suricata.alert'}
    return wanted<=alerts and wanted<=dets

def percentile(values,p):
    if not values:return None
    return sorted(values)[min(len(values)-1,int((len(values)-1)*p))]

def summary(name,ids,begin,send_elapsed,rate,recovery_at=None):
    wanted=set(ids);rows=[s for s in SAMPLES if s['at']>=begin and s['phase']==name]
    event={v['source_ip']:(at,v) for at,v in list(NORMAL.values()) if v.get('code')==str(SID) and v.get('source_ip') in wanted}
    det={v['source_ip']:(at,v) for at,v in list(DETECTIONS.values()) if v.get('source_ip') in wanted}
    alerts={v.get('src_ip') for _,v in list(EVE.values()) if v.get('alert',{}).get('signature_id')==SID and v.get('src_ip') in wanted}
    lat=[(det[ip][0]-SENT[ip]['at'])*1000 for ip in det]
    ing=[(datetime.datetime.fromisoformat(v['received_at'].replace('Z','+00:00')).timestamp()-SENT[ip]['at'])*1000 for ip,(_,v) in event.items()]
    metrics={'phase':name,'packets_sent':len(ids),'target_pps':rate,'actual_pps':len(ids)/send_elapsed,'eve_alerts':len(alerts),'normalized_alerts':len(event),'detections':len(det),'missing_alerts':len(wanted-alerts),'missing_normalized':len(wanted-set(event)),'missing_detections':len(wanted-set(det)), 'latency_ms':{'ingest_p50':percentile(ing,.5),'ingest_p95':percentile(ing,.95),'correlation_observed_p50':percentile(lat,.5),'correlation_observed_p95':percentile(lat,.95),'correlation_observed_p99':percentile(lat,.99),'correlation_observed_max':max(lat,default=0)},'peak':{key:max((r.get(key,0) for r in rows),default=0) for key in ['queue_batches','queue_bytes','queue_records','source_backlog_records','pending_normalization','pending_correlation']},'resources':{},'seconds_until_complete':time.time()-begin}
    if recovery_at:metrics['drain_after_recovery_seconds']=time.time()-recovery_at
    for process in ['suricata','sensor','siem']:
        records=[r['processes'][process] for r in rows if process in r['processes']]
        cpus=[r['cpu_percent'] for r in records if r['cpu_percent'] is not None]
        metrics['resources'][process]={'cpu_mean_percent':sum(cpus)/len(cpus) if cpus else None,'cpu_peak_percent':max(cpus,default=0),'rss_peak_mib':max((r['rss_bytes'] for r in records),default=0)/1048576}
    capture=json.loads(subprocess.check_output(['suricatasc','/lab/rules/suricata.socket','-c','iface-stat cerber-span'],text=True,timeout=5))
    assert capture['return']=='OK',capture
    metrics['capture_cumulative']=capture['message']
    RESULT['phases'].append(metrics);save('result.json',RESULT);mark(json.dumps(metrics))
    assert all(metrics[k]==0 for k in ['missing_alerts','missing_normalized','missing_detections']),metrics

def run():
    global PHASE
    # Refuse attached networking and non-empty state (no chance of running on a live SIEM).
    links=json.loads(subprocess.check_output(['ip','-j','address','show'],text=True))
    assert all(i['ifname']=='lo' or ('UP' not in i['flags'] and not i.get('addr_info')) for i in links),'requires disconnected Docker network namespace'
    assert not (ROOT/'state').exists(),'requires a fresh lab volume'
    OUT.mkdir(parents=True,exist_ok=True);(ROOT/'rules').mkdir();(ROOT/'eve').mkdir()
    rules=pathlib.Path('/input/active.rules').read_bytes()
    assert b'sid:9900001;' not in rules
    (ROOT/'rules/active.rules').write_bytes(rules+b'\nalert udp any any -> any 49000 (msg:"CERBER isolated load fixture"; content:"CERBER_LOADLAB_"; sid:9900001; rev:1;)\n')
    RESULT.update({'started_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'suricata_version':subprocess.check_output(['suricata','-V'],text=True).strip(),'rules_sha256':hashlib.sha256(rules).hexdigest(),'rules_bytes':len(rules),'architecture':os.uname().machine,'sample_interval_seconds':.5,'cpu_percent_definition':'100% = one logical CPU; shared container limit 4 CPUs','latency_definition':'Packet send to database observation; correlation bound includes up to one sample interval, not Detection.CreatedAt','traffic':'Unique-source UDP marker; full supplied ET rules plus one deterministic fixture rule; not representative throughput for arbitrary traffic'})
    subprocess.run(['seed'],check=True);subprocess.run(['seed','render'],check=True)
    yaml=ROOT/'state/suricata.yaml';s=yaml.read_text().replace('stats:\n  enabled: no','stats:\n  enabled: yes\n  interval: 1')
    # End short single-packet UDP flows promptly; record this lab override.
    s+='\nflow-timeouts:\n  udp:\n    new: 5\n    established: 5\n    closed: 0\n'
    # Distribution already contains this section: replace it, do not use duplicate keys.
    import re
    matches=list(re.finditer(r'(?m)^flow-timeouts:',s))
    if len(matches)>1:
        a=matches[0].start();m=re.search(r'(?m)^[a-zA-Z][a-zA-Z0-9_-]*:',s[matches[0].end():]);b=matches[0].end()+m.start();s=s[:a]+s[b:]
    yaml.write_text(s);RESULT['udp_flow_timeout_seconds']=5
    (ROOT/'filter.bpf').write_text('udp dst port 49000\n')
    for cmd in [['ip','link','add','cerber-span','type','veth','peer','name','cerber-tap'],['ip','link','set','cerber-span','up'],['ip','link','set','cerber-tap','up']]:subprocess.run(cmd,check=True)
    (OUT/'traffic.pcap').write_bytes(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1))
    proxy=http.server.ThreadingHTTPServer(('127.0.0.1',18791),Proxy);threading.Thread(target=proxy.serve_forever,daemon=True).start()
    server();wait(ready,'SIEM ready',60);sensor();engine()
    threading.Thread(target=sample,daemon=True).start()
    wait(lambda:'Engine started' in (OUT/'suricata.log').read_text(),'Suricata ready',120)
    RESULT['ruleset_stats']=json.loads(subprocess.check_output(['suricatasc','/lab/rules/suricata.socket','-c','ruleset-stats'],text=True,timeout=5))
    for rate in [50,200,800]:
        PHASE='steady_'+str(rate);begin=time.time();ids,elapsed=send(rate,8)
        wait(lambda:done(ids),'steady completion '+str(rate));summary(PHASE,ids,begin,elapsed,rate)
    PHASE='connection_loss_and_sensor_crash';begin=time.time();PROXY['blocked']=True
    ids,elapsed=send(100,8);wait(lambda:SAMPLES[-1].get('queue_batches',0)>0,'persisted outage queue',30)
    before=SAMPLES[-1]['queue_batches'];stop('sensor',True);sensor();time.sleep(3)
    assert PROXY['rejected']>0
    recovery=time.time();PROXY['blocked']=False
    wait(lambda:done(ids),'recovery after link and sensor crash');summary(PHASE,ids,begin,elapsed,100,recovery)
    RESULT['outage_queue_before_sensor_crash']=before
    PHASE='siem_crash';begin=time.time();stop('siem',True)
    ids,elapsed=send(100,8);server();wait(ready,'restarted SIEM',60);recovery=time.time()
    wait(lambda:done(ids),'server crash recovery');summary(PHASE,ids,begin,elapsed,100,recovery)
    PHASE='lost_ack';begin=time.time();PROXY['drop_ack']=1
    ids,elapsed=send(50,4);wait(lambda:done(ids) and PROXY['acks_dropped']==1,'lost ACK and retry')
    wait(lambda:SAMPLES[-1].get('queue_batches',1)==0,'ACK retry queue drained');summary(PHASE,ids,begin,elapsed,50)
    # Flush flow records before an idle engine restart. No claim of capturing
    # packets while the capture process is stopped.
    PHASE='suricata_restart';stop('suricata');engine();time.sleep(12)
    begin=time.time();ids,elapsed=send(50,4);wait(lambda:done(ids),'capture after engine restart');summary(PHASE,ids,begin,elapsed,50)
    stop('suricata');wait(lambda:sum(v['event_type']=='flow' for _,v in list(EVE.values()))==len(SENT),'flow flush',60)
    wait(lambda:len(NORMAL)==len(EVE) and SAMPLES[-1].get('queue_batches',1)==0 and SAMPLES[-1].get('pending_correlation',1)==0,'final full drain',360)
    time.sleep(3)
    db=connect('events.db');counts={t:db.execute('SELECT count(*) FROM '+t).fetchone()[0] for t in ['raw_events','normalized_events','detections']}
    assert counts['raw_events']==counts['normalized_events']==len(EVE)==2*len(SENT),(counts,len(EVE),len(SENT))
    assert counts['detections']==len(SENT),counts
    assert db.execute("SELECT count(*) FROM normalized_events WHERE status!='parsed'").fetchone()[0]==0
    db.close()
    assert not list((ROOT/'state').glob('*.runtime.db')) and not list((ROOT/'state').glob('*endpoint*'))
    RESULT.update({'status':'passed','packets_sent':len(SENT),'eve_records':len(EVE),'counts':counts,'proxy_faults':dict(PROXY),'sample_errors':ERRORS,'final_queue_batches':SAMPLES[-1]['queue_batches'],'finished_at':datetime.datetime.now(datetime.timezone.utc).isoformat()})
    control = connect('control.db')
    try:
        stored = control.execute('SELECT payload FROM agent_heartbeats WHERE agent_id=?', ('loadlab-sensor',)).fetchone()
        heartbeat = json.loads(stored[0])
        eve_input = next(i for i in heartbeat['sensor']['inputs'] if i['protocol'] == 'file')
        unread = eve_input.get('eve_unread_bytes')
        assert isinstance(unread, int) and unread >= 0, 'missing EVE lag in accepted heartbeat'
        RESULT['sensor_heartbeat'] = {'observed_at': heartbeat['observed_at'], 'eve_unread_bytes': unread,
                                      'queue_bytes': heartbeat['events']['queue_bytes'], 'queue_batches': heartbeat['events']['queue_batches']}
    finally:
        control.close()
    save('sent.json',SENT)
    content=(ROOT/'eve/eve.json').read_bytes()
    assert len(content.splitlines())==len(EVE),'duplicate EVE records'
    (OUT/'eve.json').write_bytes(content)
    RESULT['max_sample_interval_seconds']=max(b['at']-a['at'] for a,b in zip(SAMPLES,SAMPLES[1:]))
    save('result.json',RESULT);mark('LOAD_AND_RECOVERY_VERIFIED')

if __name__=='__main__':
    try:run()
    except Exception:
        OUT.mkdir(parents=True,exist_ok=True);RESULT['status']='failed';RESULT['error']=traceback.format_exc();save('result.json',RESULT);raise
    finally:
        STOP.set()
        for name in reversed(list(PROCS)):
            try:stop(name)
            except Exception:pass
