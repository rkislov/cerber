# SPDX-License-Identifier: Apache-2.0
"""Measure an idle sensor from appending a complete EVE line to its durable cursor."""
import base64
import datetime
import json
import math
import random
import sqlite3
import subprocess
import time

from run import OUT, ROOT, ready, save, sensor, server, stop, wait

AGENT = 'loadlab-sensor'
SOURCE = 'network:suricata'


def probe(queue, path, number):
    address = f'192.0.2.{number}'
    event = {'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
             'event_type': 'alert', 'src_ip': address, 'dest_ip': '198.51.100.1',
             'in_iface': 'cerber-span', 'proto': 'UDP', 'src_port': 40000, 'dest_port': 49000, 'flow_id': number,
             'alert': {'signature_id': 9900001, 'rev': 1, 'action': 'allowed', 'signature': 'Idle EVE probe', 'severity': 2}}
    line = (json.dumps(event) + '\n').encode()
    with path.open('ab', buffering=0) as file:
        begin = time.monotonic()
        file.write(line)
        end_offset = file.tell()
    while time.monotonic() - begin < 5:
        row = queue.execute('SELECT cursor FROM source_cursors WHERE agent_id=? AND source=?',
                            (AGENT, SOURCE)).fetchone()
        if row and row[0].startswith('r1.'):
            cursor = json.loads(base64.urlsafe_b64decode(row[0][3:] + '==='))
            if int(cursor['l'].split(':')[0]) == end_offset:
                return (time.monotonic() - begin) * 1000
        time.sleep(.002)
    raise AssertionError(f'Sensor did not commit event {number}')


def main():
    links = json.loads(subprocess.check_output(['ip', '-j', 'address'], text=True))
    assert all(i['ifname']=='lo' or ('UP' not in i['flags'] and not i.get('addr_info')) for i in links)
    assert not (ROOT/'state').exists(), 'requires fresh lab state'
    OUT.mkdir(parents=True, exist_ok=True)
    subprocess.run(['seed'], check=True)
    config_path = ROOT/'state/sensor.json'
    config = json.loads(config_path.read_text())
    config['server'] = 'http://127.0.0.1:18790'
    config_path.write_text(json.dumps(config))
    path = ROOT/'eve/eve.json'
    path.touch()
    server()
    try:
        wait(ready, 'SIEM ready', 60)
        sensor()
        try:
            queue_path = ROOT/'state/queue.db'
            wait(queue_path.exists, 'sensor spool', 15)
            with sqlite3.connect(f'file:{queue_path}?mode=ro',uri=True) as queue:
                wait(lambda: queue.execute("SELECT 1 FROM sqlite_master WHERE name='source_cursors'").fetchone(),
                     'sensor schema', 15)
                probe(queue, path, 1)  # warm up
                waits = random.Random(9900001)
                elapsed = []
                for number in range(2, 26):
                    time.sleep(waits.uniform(1.05, 1.95))
                    elapsed.append(probe(queue, path, number))
                with sqlite3.connect(f'file:{ROOT}/state/events.db?mode=ro',uri=True) as db:
                    def drained():
                        counts = [db.execute('SELECT count(*) FROM '+table).fetchone()[0]
                                  for table in ('raw_events','normalized_events','detections')]
                        return counts == [25,25,25] and queue.execute('SELECT count(*) FROM event_spool').fetchone()[0]==0
                    wait(drained, 'all 25 probes delivered and correlated', 30)
            ordered = sorted(elapsed)
            result = {'status':'passed', 'unit':'ms', 'interval_seconds':[1.05,1.95],
                      'count':len(elapsed), 'commit_latency_ms':elapsed,
                      'p50':ordered[math.ceil(.50*len(ordered))-1],
                      'p95':ordered[math.ceil(.95*len(ordered))-1], 'max':ordered[-1],
                      'packets_in_spool':0, 'detections_including_warmup':25}
            save('idle-eve.json', result)
            print(json.dumps(result),flush=True)
        finally:
            stop('sensor')
    finally:
        stop('siem')


if __name__ == '__main__':
    main()
