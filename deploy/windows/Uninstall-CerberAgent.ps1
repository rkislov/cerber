# SPDX-License-Identifier: Apache-2.0
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$service = Get-Service -Name CerberAgent -ErrorAction Stop
if ($service.Status -ne 'Stopped') {
    Stop-Service -Name CerberAgent -ErrorAction Stop
    $service.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(40))
}
& sc.exe delete CerberAgent | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Cannot remove service registration' }
Write-Output 'Service registration removed. Binary, credentials, database and event log are preserved.'
