# SPDX-License-Identifier: Apache-2.0
import sys, contextlib, datetime, time
started=False
result={'id':q['id'],'status':'failed','reboot_required':'unknown','items':[],'detail':''}
try:
    with contextlib.redirect_stdout(sys.stderr):
        import dnf, dnf.rpm
        with dnf.Base() as base:
            base.conf.read()
            base.conf.substitutions["releasever"]=dnf.rpm.detect_releasever(base.conf.installroot)
            base.conf.assumeyes=True
            base.conf.install_weak_deps=False
            base.read_all_repos()
            for repo in base.repos.iter_enabled():
                repo.gpgcheck=True
            base.fill_sack(load_system_repo=True)
            targets=[]
            for u in q['updates']:
                candidates=list(base.sack.query().available().filter(name=u['title'],arch=u['architecture'],reponame=u['repository']))
                candidates=[p for p in candidates if str(p.evr)==u['available_version'] or ('0:'+str(p.evr))==u['available_version']]
                if len(candidates)!=1: raise RuntimeError('candidate_changed')
                p=candidates[0]
                base.package_install(p,strict=True)
                targets.append(p)
            base.resolve(allow_erasing=False)
            installs=list(base.transaction.install_set)
            removes=list(base.transaction.remove_set)
            if set(str(p) for p in installs)!=set(str(p) for p in targets): raise RuntimeError('unselected_dependency_changes')
            selected={(p.name,p.arch) for p in targets}
            if any((p.name,p.arch) not in selected for p in removes): raise RuntimeError('unselected_removals')
            if q['mode']=='install':
                base.download_packages(installs)
                for p in installs:
                    code,message=base.package_signature_check(p)
                    if code!=0: raise RuntimeError('package_signature_not_trusted')
                expires=datetime.datetime.strptime(q["expires_at"][:19],"%Y-%m-%dT%H:%M:%S").replace(tzinfo=datetime.timezone.utc).timestamp()
                if time.time() >= expires: raise RuntimeError("authorization_expired")
                started=True
                base.do_transaction()
        if q['mode']=='install':
            with dnf.Base() as verify:
                verify.conf.read()
                verify.fill_sack(load_system_repo=True,load_available_repos=False)
                installed=list(verify.sack.query().installed())
                for u in q['updates']:
                    found=any(p.name==u['title'] and p.arch==u['architecture'] and (str(p.evr)==u['available_version'] or '0:'+str(p.evr)==u['available_version']) for p in installed)
                    result['items'].append({'id':u['id'],'status':'installed' if found else 'failed','code':'target_version_observed' if found else 'target_version_missing'})
        else:
            result['items']=[{'id':u['id'],'status':'ready','code':'applicable'} for u in q['updates']]
    good=sum(i['status'] in ('ready','installed') for i in result['items'])
    result['status']='succeeded' if good==len(q['updates']) else 'partial' if good else 'failed'
except Exception:
    # An exception may occur after the RPM transaction started: never claim rollback or retry blindly.
    result['status']='unknown' if started else 'failed'
    result['detail']='DNF transaction unavailable or changed; inspect native history before retry'
    result['items']=[{'id':u['id'],'status':'unknown' if started else 'failed','code':'dnf_transaction_failed'} for u in q['updates']]
print(json.dumps(result))
