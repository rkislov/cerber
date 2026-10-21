#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Install nonterminal netfilter logging. Never installs/enables a firewall policy."""
import argparse, datetime, ipaddress, json, os, pathlib, shutil, subprocess, sys
os.environ['PATH']='/usr/sbin:/usr/bin:/sbin:/bin'
CONFIG=pathlib.Path('/etc/cerber/firewall-logging.json')
HELPER=pathlib.Path('/usr/local/libexec/cerber-firewall-logging')
UNIT=pathlib.Path('/etc/systemd/system/cerber-firewall-logging.service')
TABLE='cerber_observe'
CHAINS=[('INPUT','CERBER_INPUT_LOG'),('OUTPUT','CERBER_OUTPUT_LOG')]
def run(args,check=True):
 return subprocess.run(args,check=check,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
def ipt(binary,args,check=True):return run([binary,'-w','10']+args,check)
def exists_table():return run(['nft','list','table','inet',TABLE],False).returncode==0
def check_drop(cfg):
 if not cfg.get('drop_output_address'):return None
 args=['-d',cfg['drop_output_address'],'-p','tcp','--dport',str(cfg['drop_output_port']),'--tcp-flags','RST','RST']
 if ipt('iptables',['-C','OUTPUT']+args+['-j','DROP'],False).returncode:raise RuntimeError('Expected existing OUTPUT DROP is absent; no mirror logging installed')
 return args
def remove(cfg):
 if cfg['backend']=='nft':
  if exists_table():run(['nft','delete','table','inet',TABLE])
 else:
  for binary in ['iptables','ip6tables']:
   if not shutil.which(binary):continue
   for parent,chain in CHAINS:
    while ipt(binary,['-C',parent,'-j',chain],False).returncode==0:ipt(binary,['-D',parent,'-j',chain])
    if ipt(binary,['-S',chain],False).returncode==0:ipt(binary,['-F',chain]);ipt(binary,['-X',chain])
def apply(cfg):
 if cfg['backend']=='nft':
  if exists_table():raise RuntimeError('Managed nft table already exists; restart the service instead of appending')
  rules='''table inet cerber_observe {
 chain input {
  type filter hook input priority -301; policy accept;
  tcp flags & (syn | ack) == syn limit rate 10/second burst 40 packets log prefix "CERBER_NFT_SYN " level info
 }
}
'''
  subprocess.run(['nft','-c','-f','-'],input=rules,text=True,check=True)
  subprocess.run(['nft','-f','-'],input=rules,text=True,check=True)
 else:
  mirror=check_drop(cfg)
  try:
   for binary in ['iptables','ip6tables']:
    if not shutil.which(binary):continue
    if ipt(binary,['-S','CERBER_INPUT_LOG'],False).returncode==0:raise RuntimeError('Managed iptables chain already exists; restart service')
    ipt(binary,['-N','CERBER_INPUT_LOG'])
    ipt(binary,['-A','CERBER_INPUT_LOG','-p','tcp','--syn','-m','limit','--limit','10/second','--limit-burst','40','-j','LOG','--log-prefix','CERBER_IPT_SYN ','--log-level','6'])
    ipt(binary,['-I','INPUT','1','-j','CERBER_INPUT_LOG'])
   if mirror:
    ipt('iptables',['-N','CERBER_OUTPUT_LOG'])
    ipt('iptables',['-A','CERBER_OUTPUT_LOG']+mirror+['-m','limit','--limit','10/second','--limit-burst','40','-j','LOG','--log-prefix','CERBER_IPT_DROP ','--log-level','6'])
    ipt('iptables',['-I','OUTPUT','1','-j','CERBER_OUTPUT_LOG'])
  except Exception:
   remove(cfg);raise

def save_snapshot(folder):
 for name,cmd in [('iptables.rules',['iptables-save']),('ip6tables.rules',['ip6tables-save']),('nft.json',['nft','-j','list','ruleset'])]:
  if shutil.which(cmd[0]):(folder/name).write_text(run(cmd).stdout)
def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--action',choices=['install','apply','remove'],default='install')
 p.add_argument('--backend',choices=['nft','iptables'],default='nft')
 p.add_argument('--drop-output-address');p.add_argument('--drop-output-port',type=int)
 p.add_argument('--ufw-level',choices=['low','medium','high','full'])
 a=p.parse_args()
 if os.geteuid()!=0:raise SystemExit('Run as root/sudo')
 if a.action!='install':
  if CONFIG.is_symlink() or CONFIG.stat().st_uid!=0 or CONFIG.stat().st_mode&0o022:raise SystemExit('Config must be root-owned and not writable by others')
  cfg=json.loads(CONFIG.read_text());(apply if a.action=='apply' else remove)(cfg);return
 if not shutil.which('nft' if a.backend=='nft' else 'iptables'):raise SystemExit('Install the selected firewall CLI first; this installer never enables firewall services')
 cfg=dict(backend=a.backend)
 if a.drop_output_address:
  if a.backend!='iptables' or not a.drop_output_port or not 1<=a.drop_output_port<=65535:raise SystemExit('DROP mirror requires iptables and a valid port')
  cfg.update(drop_output_address=str(ipaddress.IPv4Network(a.drop_output_address,strict=False)),drop_output_port=a.drop_output_port)
  check_drop(cfg)
 managed=CONFIG.exists()
 if not managed:
  if a.backend=='nft' and exists_table():raise SystemExit('Refusing a pre-existing unmanaged table')
  if a.backend=='iptables' and any(ipt('iptables',['-S',chain],False).returncode==0 for _,chain in CHAINS):raise SystemExit('Refusing pre-existing unmanaged chains')
 backup=pathlib.Path('/var/lib/cerber/firewall-backups')/(datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+str(os.getpid()))
 backup.mkdir(parents=True,mode=0o700);os.chmod(backup,0o700);save_snapshot(backup)
 for path in [CONFIG,HELPER,UNIT]:
  if path.is_symlink():raise SystemExit('Managed path symlink refused')
  if path.exists():shutil.copy2(path,backup/path.name)
 if managed:run(['systemctl','stop','cerber-firewall-logging.service'])
 CONFIG.parent.mkdir(mode=0o750,parents=True,exist_ok=True)
 CONFIG.write_text(json.dumps(cfg,indent=2));os.chown(CONFIG,0,0);os.chmod(CONFIG,0o600)
 HELPER.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
 if pathlib.Path(__file__).resolve()!=HELPER:shutil.copyfile(__file__,HELPER)
 os.chown(HELPER,0,0);os.chmod(HELPER,0o755)
 UNIT.write_text('''[Unit]
Description=Cerber nonterminal firewall logging
After=network-pre.target ufw.service nftables.service
Before=cerber-agent.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/libexec/cerber-firewall-logging --action apply
ExecStop=/usr/local/libexec/cerber-firewall-logging --action remove
[Install]
WantedBy=multi-user.target
''');os.chmod(UNIT,0o644)
 try:
  run(['systemctl','daemon-reload']);run(['systemctl','enable','--now','cerber-firewall-logging.service'])
  if a.ufw_level and shutil.which('ufw'):
   before=run(['ufw','status']).stdout
   run(['ufw','logging',a.ufw_level])
   after=run(['ufw','status']).stdout
   if ('Status: inactive' in before)!=('Status: inactive' in after):raise RuntimeError('UFW activation unexpectedly changed')
  after=backup/'after';after.mkdir(mode=0o700);save_snapshot(after)
 except Exception:
  run(['systemctl','disable','--now','cerber-firewall-logging.service'],False)
  raise
 print(json.dumps(dict(backend=a.backend,backup=str(backup),logging_only=True)))
if __name__=='__main__':
 try:main()
 except subprocess.CalledProcessError as e:print(e.stderr or str(e),file=sys.stderr);sys.exit(1)
