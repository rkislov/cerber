#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Isolated Samba AD fixture, not a replacement for an organization's directory."""
import json
import os
from pathlib import Path
from samba.auth import system_session
from samba.provision import provision
from samba.samdb import SamDB
from samba.param import LoadParm

private = Path('/var/lib/samba/private/sam.ldb')
tls_dir = Path('/var/lib/samba/private/cerber-tls')
tls_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
for name in ['server.key', 'server.pem', 'ca.pem']:
    target = tls_dir / name
    target.write_bytes((Path('/run/directory-secrets') / name).read_bytes())
    target.chmod(0o600)
secrets = json.loads(Path('/run/directory-secrets/credentials.json').read_text())
if not private.exists():
    # Only LDAPS is published. SYSVOL ACLs are unnecessary for this LDAP-only
    # test domain; bypassing their setup avoids privileged containers.
    provision(logger=__import__('logging').getLogger('directory-lab'),
              session_info=system_session(), targetdir='/var/lib/samba',
              realm='SIEM.LAB.INTERNAL', domain='SIEMLAB', hostname='dc-siem-lab',
              serverrole='active directory domain controller',
              dns_backend='SAMBA_INTERNAL', adminpass=secrets['administrator'],
              use_rfc2307=True, skip_sysvolacl=True)
    config = Path('/var/lib/samba/etc/smb.conf')
    text = config.read_text().replace('[global]', '''[global]
        tls enabled = yes
        tls keyfile = /var/lib/samba/private/cerber-tls/server.key
        tls certfile = /var/lib/samba/private/cerber-tls/server.pem
        tls cafile = /var/lib/samba/private/cerber-tls/ca.pem
        ldap server require strong auth = yes
        log level = 0
        max log size = 1024''')
    config.write_text(text)
    lp = LoadParm()
    lp.load(str(config))
    db = SamDB(url=str(private), session_info=system_session(), lp=lp)
    for name in ['cerber-reader', 'alice', 'bob', 'disabled-user']:
        db.newuser(name, secrets[name])
    db.disable_account('(sAMAccountName=disabled-user)')
    # cerber-reader remains an ordinary Domain Users member, never an admin.
config = Path('/var/lib/samba/etc/smb.conf')
config.write_text(config.read_text().replace('/run/directory-secrets/', '/var/lib/samba/private/cerber-tls/'))
os.execvp('samba', ['samba', '--foreground', '--no-process-group', '--configfile=/var/lib/samba/etc/smb.conf'])
