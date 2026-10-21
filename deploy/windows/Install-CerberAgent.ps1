# SPDX-License-Identifier: Apache-2.0
# Run elevated after provisioning agent.json, credentials and local asset DB.
# Installs only into fixed Program Files / ProgramData directories; does not start.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$Binary, [switch]$Privileged)
$ErrorActionPreference = 'Stop'
$name = 'CerberAgent'
$program = Join-Path $env:ProgramFiles 'Cerber'
$root = Join-Path $env:ProgramData 'Cerber'
$configDir = Join-Path $root 'config'
$stateDir = Join-Path $root 'state'
$configPath = Join-Path $configDir 'agent.json'
$destination = Join-Path $program 'cerber.exe'
if (Get-Service -Name $name -ErrorAction SilentlyContinue) { throw 'CerberAgent already exists; stop/remove it before replacing its binary. Data is preserved.' }
$source = (Resolve-Path -LiteralPath $Binary).ProviderPath
if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) { throw "Provision $configPath first" }
# Validate without opening the database or printing credentials.
& $source agent validate-config -config $configPath
if ($LASTEXITCODE -ne 0) { throw 'Agent config validation failed' }
$config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
function Assert-Contained([string]$Path,[string]$Parent) {
    $full = [IO.Path]::GetFullPath($Path)
    $prefix = [IO.Path]::GetFullPath($Parent).TrimEnd('\') + '\'
    if (-not $full.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)) { throw 'Service inputs must reside in fixed Cerber directories' }
}
Assert-Contained $config.database $stateDir
Assert-Contained $config.credentials $configDir
if ($config.ca_cert) { Assert-Contained $config.ca_cert $configDir }
if (-not (Test-Path -LiteralPath $config.database -PathType Leaf)) { throw 'Create the local asset database before installation' }
# Refuse junctions/symlinks in managed trees before modifying ACLs or copying files.
foreach ($dir in @($program,$root,$configDir,$stateDir)) {
    if (Test-Path -LiteralPath $dir) {
        if ((Get-Item -LiteralPath $dir -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse points are not supported in managed directories' }
    } else { [void](New-Item -ItemType Directory -Path $dir) }
}
foreach ($dir in @($program,$root)) {
    foreach ($item in (Get-ChildItem -LiteralPath $dir -Force -Recurse)) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse points are not supported in managed directories' }
    }
}
Copy-Item -LiteralPath $source -Destination $destination -Force
# LocalService is deliberately unprivileged. Service SID grants are specific to this service.
$password = New-Object Security.SecureString
$identity = New-Object Management.Automation.PSCredential('NT AUTHORITY\LocalService',$password)
$created = $false
try {
    $command = '"'+$destination+'" agent service-run -config "'+$configPath+'"'
    if ($Privileged) {
        New-Service -Name $name -DisplayName 'Cerber Agent' -BinaryPathName $command -StartupType Manual | Out-Null
    } else {
        New-Service -Name $name -DisplayName 'Cerber Agent' -BinaryPathName $command -StartupType Manual -Credential $identity | Out-Null
    }
    $created = $true
    & sc.exe sidtype $name unrestricted | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot enable service SID' }
    $sid = (New-Object Security.Principal.NTAccount('NT SERVICE\CerberAgent')).Translate([Security.Principal.SecurityIdentifier])
    function Set-PrivateAcl([string]$Path,[Security.AccessControl.FileSystemRights]$Rights) {
        $item = Get-Item -LiteralPath $Path -Force
        $acl = if ($item.PSIsContainer) { New-Object Security.AccessControl.DirectorySecurity } else { New-Object Security.AccessControl.FileSecurity }
        $acl.SetAccessRuleProtection($true,$false)
        foreach ($grant in @(@('S-1-5-18','FullControl'),@('S-1-5-32-544','FullControl'),@($sid.Value,[string]$Rights))) {
            $principal = New-Object Security.Principal.SecurityIdentifier($grant[0])
            if ($item.PSIsContainer) {
                $rule = New-Object Security.AccessControl.FileSystemAccessRule($principal,$grant[1],'ContainerInherit,ObjectInherit','None','Allow')
            } else { $rule = New-Object Security.AccessControl.FileSystemAccessRule($principal,$grant[1],'Allow') }
            $acl.AddAccessRule($rule)
        }
        Set-Acl -LiteralPath $Path -AclObject $acl
    }
    foreach ($dir in @($program,$root)) {
        Set-PrivateAcl $dir 'ReadAndExecute'
        foreach ($item in (Get-ChildItem -LiteralPath $dir -Force -Recurse)) { Set-PrivateAcl $item.FullName 'ReadAndExecute' }
    }
    Set-PrivateAcl $stateDir 'Modify'
    foreach ($item in (Get-ChildItem -LiteralPath $stateDir -Force -Recurse)) { Set-PrivateAcl $item.FullName 'Modify' }
    if (-not [Diagnostics.EventLog]::SourceExists($name)) { New-EventLog -LogName Application -Source $name -MessageResourceFile (Join-Path $env:SystemRoot 'System32\EventCreate.exe') }
    & sc.exe failure $name reset= 86400 actions= restart/30000/restart/60000/restart/300000 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot configure service recovery' }
    & sc.exe failureflag $name 1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot enable non-crash recovery' }
    & sc.exe config $name start= delayed-auto | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot configure automatic service startup' }
    Write-Output 'CerberAgent installed. Start-Service CerberAgent; inspect Application log / source CerberAgent.'
} catch {
    if ($created) { & sc.exe delete $name | Out-Null }
    throw
}
