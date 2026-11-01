#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build native binaries, run in a fresh disconnected Docker namespace, export evidence."""
import argparse, datetime, hashlib, json, os, pathlib, shutil, subprocess, uuid

def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rules',required=True,type=pathlib.Path,help='Local ET Open .rules snapshot (never downloaded by the runtime)')
    parser.add_argument('--output',required=True,type=pathlib.Path,help='New local output directory; contains synthetic packet captures and metrics')
    args=parser.parse_args();repo=pathlib.Path(__file__).resolve().parents[2]
    rules=args.rules.resolve();out=args.output.resolve()
    if not rules.is_file() or out.exists():parser.error('rules must exist and output must be a new directory')
    info=json.loads(subprocess.check_output(['docker','info','--format','{{json .}}'],text=True))
    arch={'aarch64':'arm64','arm64':'arm64','x86_64':'amd64','amd64':'amd64'}.get(info['Architecture'])
    if not arch:parser.error('Docker architecture must be arm64 or x86_64')
    if info['MemTotal']<5*1024**3:parser.error('Docker needs at least 5 GiB available memory configuration')
    out.mkdir(parents=True,mode=0o700);build=out/'build';build.mkdir();inputs=out/'input';inputs.mkdir()
    shutil.copyfile(rules,inputs/'active.rules')
    shutil.copyfile(repo/'test/loadlab/Dockerfile',build/'Dockerfile')
    env=dict(os.environ,CGO_ENABLED='0',GOOS='linux',GOARCH=arch)
    for name,source in [('cerber','./cmd/cerber'),('cerber-sensor','./cmd/cerber-sensor'),('seed','./test/loadlab/seed')]:
        run('go','build','-trimpath','-o',str(build/name),source,cwd=repo,env=env)
    name='cerber-loadlab-'+uuid.uuid4().hex[:12];volume=name;image=name+':local'
    manifest={'started_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip(),'architecture':arch,'docker_cpus':info['NCPU'],'docker_memory_bytes':info['MemTotal'],'container_cpus':4,'container_memory_bytes':4*1024**3,'rules_sha256':hashlib.sha256(rules.read_bytes()).hexdigest(),'network':'none','capabilities':['NET_ADMIN','NET_RAW'],'binaries':{n:hashlib.sha256((build/n).read_bytes()).hexdigest() for n in ['cerber','cerber-sensor','seed']}}
    (out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    with (out/'build.log').open('w') as log:run('docker','build','-t',image,str(build),stdout=log,stderr=subprocess.STDOUT)
    run('docker','volume','create',volume,stdout=subprocess.DEVNULL)
    try:
        with (out/'run.log').open('w') as log:
            completed=subprocess.run(['docker','run','--name',name,'--network','none','--cap-drop','ALL','--cap-add','NET_ADMIN','--cap-add','NET_RAW','--read-only','--memory','4g','--cpus','4','--pids-limit','128','--tmpfs','/tmp:rw,noexec,nosuid,size=64m','--tmpfs','/run:rw,noexec,nosuid,size=16m','--mount','type=volume,src='+volume+',dst=/lab','--mount','type=bind,src='+str(inputs)+',dst=/input,readonly','--mount','type=bind,src='+str(repo/'test/loadlab')+',dst=/scripts,readonly',image,'python3','/scripts/run.py'],stdout=log,stderr=subprocess.STDOUT,timeout=1200)
        if completed.returncode:raise RuntimeError('Lab failed; inspect run.log and evidence/result.json')
    finally:
        subprocess.run(['docker','stop','-t','30',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        inspection=subprocess.run(['docker','inspect',name],capture_output=True,text=True)
        if inspection.returncode==0:
            (out/'container.json').write_text(inspection.stdout)
            run('docker','cp',name+':/lab/evidence',str(out/'evidence'))
            run('docker','rm',name,stdout=subprocess.DEVNULL)
        run('docker','volume','rm',volume,stdout=subprocess.DEVNULL)
        run('docker','image','rm',image,stdout=subprocess.DEVNULL)
    print('Evidence:',out/'evidence/result.json')

if __name__=='__main__':main()
