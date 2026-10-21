#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
binary= config= server= credentials= address=127.0.0.1 name=localhost
privileged=false start=false refresh=false
while [ "$#" -gt 0 ]; do
 case "$1" in
 --binary) binary=$2; shift 2;; --config) config=$2; shift 2;;
 --server) server=$2; shift 2;; --credentials) credentials=$2; shift 2;;
 --address) address=$2; shift 2;; --name) name=$2; shift 2;;
 --privileged) privileged=true; shift;; --start) start=true; shift;;
 --refresh-metadata) refresh=true; shift;;
 *) echo "Unknown option: $1" >&2; exit 2;; esac
done
[ "$(id -u)" = 0 ] || { echo 'Run installer with sudo/root' >&2; exit 1; }
[ -n "$binary" ] && [ -f "$binary" ] && [ ! -L "$binary" ] || { echo '--binary regular file required' >&2; exit 1; }
command -v python3 >/dev/null
command -v systemctl >/dev/null
if "$privileged"; then command -v sudo >/dev/null; command -v visudo >/dev/null; fi
if "$refresh" && ! "$privileged"; then echo '--refresh-metadata requires --privileged' >&2; exit 1; fi
for path in /opt/cerber /etc/cerber /var/lib/cerber /etc/systemd/system/cerber-agent.service.d /etc/sudoers.d/cerber-agent; do
 [ ! -L "$path" ] || { echo "Refusing symlink: $path" >&2; exit 1; }
done
if [ -d /var/lib/cerber ] && find /var/lib/cerber -type l | read -r ignored; then echo 'Refusing symlinks in managed state' >&2; exit 1; fi
if ! id cerber >/dev/null 2>&1; then useradd --system --user-group --home-dir /var/lib/cerber --no-create-home --shell /usr/sbin/nologin cerber; fi
if getent group systemd-journal >/dev/null; then usermod -a -G systemd-journal cerber; fi
systemctl stop cerber-agent.service 2>/dev/null || true
install -d -o root -g root -m 755 /opt/cerber
install -d -o root -g cerber -m 750 /etc/cerber
install -d -o cerber -g cerber -m 700 /var/lib/cerber
backup=/var/lib/cerber/install-backups/$(date -u +%Y%m%dT%H%M%SZ)-$$
install -d -o root -g root -m 700 "$backup"
for old in /opt/cerber/cerber /etc/cerber/agent.json /etc/systemd/system/cerber-agent.service /etc/systemd/system/cerber-agent.service.d/20-privileges.conf /etc/sudoers.d/cerber-agent; do
 if [ -f "$old" ]; then cp -p "$old" "$backup/$(echo "$old" | tr / _)"; fi
done
if [ "$binary" != /opt/cerber/cerber ]; then install -o root -g root -m 755 "$binary" /opt/cerber/cerber; fi
chown root:root /opt/cerber/cerber
chmod 755 /opt/cerber/cerber
if [ -n "$credentials" ] && [ "$credentials" != /etc/cerber/credentials.json ]; then install -o root -g cerber -m 640 "$credentials" /etc/cerber/credentials.json; fi
if [ -n "$config" ] && [ "$config" != /etc/cerber/agent.json ]; then install -o root -g cerber -m 640 "$config" /etc/cerber/agent.json; fi
if [ ! -f /etc/cerber/agent.json ]; then
 [ -n "$server" ] && [ -f /etc/cerber/credentials.json ] || { echo 'Provide --config or --server and --credentials' >&2; exit 1; }
 /opt/cerber/cerber -db /var/lib/cerber/agent.db asset add -ip "$address" -name "$name" > "$backup/local-asset.json"
 python3 - "$server" "$backup/local-asset.json" <<'PY'
import json,sys
asset=json.load(open(sys.argv[2]))['id']
config=dict(schema_version=1,database='/var/lib/cerber/agent.db',asset_id=asset,credentials='/etc/cerber/credentials.json',server=sys.argv[1],interval='1h',heartbeat_interval='1m',check_windows_updates=False,check_package_updates=True,refresh_package_metadata=False,package_manager='auto',event_sources='journald')
with open('/etc/cerber/agent.json','w') as f:json.dump(config,f,indent=2)
PY
fi
# Reject writable service input paths: the exact sudo command executes this config as root.
python3 - "$refresh" <<'PY'
import json,os,stat,sys
path='/etc/cerber/agent.json'
if os.path.islink(path):raise SystemExit('Config symlink refused')
c=json.load(open(path))
if c.get('database')!='/var/lib/cerber/agent.db':raise SystemExit('Installer requires fixed /var/lib/cerber/agent.db')
for key in ['credentials','ca_cert','patch_inbox','patch_outbox']:
 p=c.get(key)
 if not p:continue
 if key.startswith('patch_'):
  expected='/var/lib/cerber-patch/'+('inbox' if key=='patch_inbox' else 'outbox')
  if p!=expected:raise SystemExit('Patch paths must use /var/lib/cerber-patch/inbox and outbox')
  for directory in ['/var/lib/cerber-patch',p]:
   st=os.lstat(directory)
   if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0:raise SystemExit('Patch directories must be real root-owned directories')
  continue
 if os.path.commonpath([os.path.abspath(p),'/etc/cerber'])!='/etc/cerber':raise SystemExit('Credentials/CA must be inside /etc/cerber')
 if os.path.islink(p):raise SystemExit('Input symlink refused')
 os.chown(p,0,__import__('grp').getgrnam('cerber').gr_gid);os.chmod(p,0o640)
if sys.argv[1]=='true':c['check_package_updates']=True;c['refresh_package_metadata']=True
with open(path,'w') as f:json.dump(c,f,indent=2)
os.chown(path,0,__import__('grp').getgrnam('cerber').gr_gid);os.chmod(path,0o640)
PY
# State is private; preserve existing assets, queue and cursors through an upgrade.
find /var/lib/cerber -path /var/lib/cerber/install-backups -prune -o -exec chown cerber:cerber {} \;
/opt/cerber/cerber agent validate-config -config /etc/cerber/agent.json
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
install -m 644 "$script_dir/cerber-agent.service" /etc/systemd/system/cerber-agent.service
install -d -m 755 /etc/systemd/system/cerber-agent.service.d
if "$privileged"; then
 if getent group sudo >/dev/null; then usermod -a -G sudo cerber; elif getent group wheel >/dev/null; then usermod -a -G wheel cerber; fi
 sudo_path=$(command -v sudo)
 tmp=$(mktemp /etc/sudoers.d/.cerber-agent.XXXXXX)
 trap 'rm -f "$tmp"' EXIT HUP INT TERM
 echo 'cerber ALL=(root) NOPASSWD: /opt/cerber/cerber agent run -config /etc/cerber/agent.json' > "$tmp"
 chmod 440 "$tmp"
 visudo -cf "$tmp"
 mv "$tmp" /etc/sudoers.d/cerber-agent
 trap - EXIT HUP INT TERM
 cat > /etc/systemd/system/cerber-agent.service.d/20-privileges.conf <<PROFILE
[Service]
ExecStart=
ExecStart=$sudo_path -n /opt/cerber/cerber agent run -config /etc/cerber/agent.json
NoNewPrivileges=false
ProtectSystem=false
ProtectHome=false
PrivateTmp=false
ReadWritePaths=
PROFILE
else
 rm -f /etc/systemd/system/cerber-agent.service.d/20-privileges.conf /etc/sudoers.d/cerber-agent
fi
systemd-analyze verify /etc/systemd/system/cerber-agent.service
systemctl daemon-reload
systemctl enable cerber-agent.service
if "$start"; then systemctl start cerber-agent.service; systemctl is-active cerber-agent.service; fi
echo "Installed; privileged=$privileged; backup=$backup"
