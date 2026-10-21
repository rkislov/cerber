# SPDX-License-Identifier: Apache-2.0
# Elevated installation only. Does not start the task or change Windows Update policies.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$Binary,
      [Parameter(Mandatory=$true)][string]$PublicKey,
      [Parameter(Mandatory=$true)][ValidatePattern('^[a-zA-Z0-9_-]{1,128}$')][string]$AgentID)
$ErrorActionPreference='Stop'
$name='CerberPatchExecutor'
$root=Join-Path $env:ProgramData 'CerberPatch'
$program=Join-Path $env:ProgramFiles 'CerberPatch'
if(Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue){throw 'Executor already installed; preserve state and stop it before updating'}
$source=(Resolve-Path -LiteralPath $Binary).ProviderPath
$keySource=(Resolve-Path -LiteralPath $PublicKey).ProviderPath
$key=Get-Content -LiteralPath $keySource -Raw | ConvertFrom-Json
if([Convert]::FromBase64String([string]$key).Length -ne 32){throw 'Invalid public key'}
$sid=(New-Object Security.Principal.NTAccount('NT SERVICE\CerberAgent')).Translate([Security.Principal.SecurityIdentifier])
foreach($path in @($root,$program)){
 if(Test-Path -LiteralPath $path){throw 'Executor installation directories must be new; never discard an existing execution journal'}
}
function Set-ExecutorAcl([string]$Path,[string]$AgentRights){
 $item=Get-Item -LiteralPath $Path -Force
 $acl=if($item.PSIsContainer){New-Object Security.AccessControl.DirectorySecurity}else{New-Object Security.AccessControl.FileSecurity}
 $acl.SetAccessRuleProtection($true,$false)
 $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
 $grants=@(@('S-1-5-18','FullControl'),@('S-1-5-32-544','FullControl'))
 if($AgentRights){$grants+=,@($sid.Value,$AgentRights)}
 foreach($grant in $grants){
  $principal=New-Object Security.Principal.SecurityIdentifier($grant[0])
  $rule=if($item.PSIsContainer){New-Object Security.AccessControl.FileSystemAccessRule($principal,$grant[1],'ContainerInherit,ObjectInherit','None','Allow')}else{New-Object Security.AccessControl.FileSystemAccessRule($principal,$grant[1],'Allow')}
  $acl.AddAccessRule($rule)
 }
 Set-Acl -LiteralPath $Path -AclObject $acl
}
foreach($dir in @($root,$program)){New-Item -ItemType Directory -Path $dir | Out-Null;Set-ExecutorAcl $dir 'ReadAndExecute'}
foreach($dir in @('inbox','outbox','private')){New-Item -ItemType Directory -Path (Join-Path $root $dir) | Out-Null}
Set-ExecutorAcl (Join-Path $root 'inbox') 'Modify'
Set-ExecutorAcl (Join-Path $root 'outbox') 'ReadAndExecute'
Set-ExecutorAcl (Join-Path $root 'private') ''
$destination=Join-Path $program 'cerber.exe'
Copy-Item -LiteralPath $source -Destination $destination
Copy-Item -LiteralPath $keySource -Destination (Join-Path $root 'signing.pub')
$config=@{agent_id=$AgentID;public_key=(Join-Path $root 'signing.pub');inbox=(Join-Path $root 'inbox');outbox=(Join-Path $root 'outbox');state=(Join-Path $root 'private\executor.db');manager='wua'}
$configPath=Join-Path $root 'executor.json'
[IO.File]::WriteAllText($configPath,($config|ConvertTo-Json),(New-Object Text.UTF8Encoding($false)))
foreach($path in @($destination,$configPath,(Join-Path $root 'signing.pub'))){Set-ExecutorAcl $path 'ReadAndExecute'}
$action=New-ScheduledTaskAction -Execute $destination -Argument ('patch executor -config "'+$configPath+'"')
$trigger=New-ScheduledTaskTrigger -AtStartup
$settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
$principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger -Settings $settings -Principal $principal | Out-Null
Write-Output 'Executor installed but not started. Add patch_inbox/patch_outbox to the agent config, then start the task and restart CerberAgent.'
