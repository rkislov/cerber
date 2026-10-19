# SPDX-License-Identifier: Apache-2.0
# Read-only collector. No Win32_Product, downloads, installations or policy changes.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$coverage = New-Object System.Collections.ArrayList
$components = New-Object System.Collections.ArrayList
$updates = New-Object System.Collections.ArrayList
function Coverage($section, $status, $detail) {
    [void]$coverage.Add(@{section=$section;status=$status;detail=([string]$detail).Substring(0,[Math]::Min(4096,([string]$detail).Length))})
}
$osInfo = @{family='windows';name='';version='';build='';edition='';architecture=''}
try {
    $os = Get-CimInstance Win32_OperatingSystem
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $nativeArch = [Environment]::GetEnvironmentVariable('PROCESSOR_ARCHITECTURE','Machine')
    $arch = switch ($nativeArch) { 'AMD64' { 'x64' }; 'ARM64' { 'arm64' }; 'x86' { 'x86' }; default { throw 'Unknown native Windows architecture' } }
    $osInfo = @{family='windows';name=[string]$os.Caption;version=[string]$os.Version;build=([string]$os.BuildNumber+'.'+[string]$cv.UBR);edition=[string]$cv.EditionID;architecture=$arch}
    Coverage 'os' 'complete' 'Win32_OperatingSystem and CurrentVersion registry; build includes UBR'
} catch { Coverage 'os' 'error' $_.Exception.Message }
Coverage 'packages' 'unsupported' 'Windows package-manager inventory is not implemented'
# Registry registration is not a complete census of portable, Store and other-user applications.
$appErrors = 0
$currentSID = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
foreach ($hive in @([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryHive]::CurrentUser)) {
    foreach ($view in @([Microsoft.Win32.RegistryView]::Registry64,[Microsoft.Win32.RegistryView]::Registry32)) {
        $base = $null; $root = $null
        try {
            $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive,$view)
            $root = $base.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')
            if ($null -eq $root) { continue }
            foreach ($name in $root.GetSubKeyNames()) {
                $item = $null
                try {
                    $item = $root.OpenSubKey($name)
                    if ($null -eq $item) { continue }
                    $displayName = [string]$item.GetValue('DisplayName')
                    if ([string]::IsNullOrWhiteSpace($displayName)) { continue }
                    $scope = [string]$hive
                    if ($hive -eq [Microsoft.Win32.RegistryHive]::CurrentUser) { $scope += ':'+$currentSID }
                    $identity = ($scope+':'+[string]$view+':'+$name).ToLowerInvariant()
                    [void]$components.Add(@{id=('windows:registry:'+$identity);kind='application';name=$displayName;version=[string]$item.GetValue('DisplayVersion');publisher=[string]$item.GetValue('Publisher');source='windows-uninstall-registry';product_key=$identity;architecture=''})
                } catch { $appErrors++ } finally { if ($null -ne $item) { $item.Dispose() } }
            }
        } catch { $appErrors++ } finally {
            if ($null -ne $root) { $root.Dispose() }; if ($null -ne $base) { $base.Dispose() }
        }
    }
}
Coverage 'applications' 'partial' ('HKLM/HKCU uninstall registry, 32/64-bit views; excludes other users/portable/Store inventory; errors='+$appErrors)
try {
    foreach ($feature in (Get-WindowsOptionalFeature -Online -ErrorAction Stop)) {
        if ($null -ne $feature.FeatureName) {
            [void]$components.Add(@{id=('windows:feature:'+$feature.FeatureName.ToLowerInvariant());kind='component';state=[string]$feature.State;name=[string]$feature.FeatureName;version='';publisher='Microsoft';source='windows-optional-features';product_key=[string]$feature.FeatureName;architecture=$osInfo.architecture})
        }
    }
    Coverage 'components' 'partial' 'Windows optional features and states; not a complete servicing package list'
} catch { Coverage 'components' 'error' $_.Exception.Message }
try {
    $session = New-Object -ComObject Microsoft.Update.Session
    $session.ClientApplicationID = 'Cerber inventory'
    $searcher = $session.CreateUpdateSearcher()
    $searcher.Online = $false
    $result = $searcher.Search("IsInstalled=1 and Type='Software'")
    if ([int]$result.ResultCode -notin @(2,3)) { throw ('WUA search failed with result code '+$result.ResultCode) }
    for ($i=0; $i -lt $result.Updates.Count; $i++) {
        $update = $result.Updates.Item($i)
        [void]$updates.Add(@{id=[string]$update.Identity.UpdateID;revision=[int]$update.Identity.RevisionNumber;title=[string]$update.Title;kbs=@($update.KBArticleIDs | ForEach-Object { [string]$_ });state='installed';source='windows-update-agent-local-cache'})
    }
    Coverage 'updates_installed' 'partial' ('WUA local metadata; result code='+$result.ResultCode+'; not a complete CBS/MSI update inventory')
} catch { Coverage 'updates_installed' 'error' $_.Exception.Message }
if ($CheckAvailable) {
    try {
        $session = New-Object -ComObject Microsoft.Update.Session
        $session.ClientApplicationID = 'Cerber applicability check'
        $searcher = $session.CreateUpdateSearcher()
        # Use the machine's configured update service (including managed WSUS).
        $searcher.Online = $true
        $result = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
        if ([int]$result.ResultCode -notin @(2,3)) { throw ('WUA search failed with result code '+$result.ResultCode) }
        for ($i=0; $i -lt $result.Updates.Count; $i++) {
            $update = $result.Updates.Item($i)
            [void]$updates.Add(@{id=[string]$update.Identity.UpdateID;revision=[int]$update.Identity.RevisionNumber;title=[string]$update.Title;kbs=@($update.KBArticleIDs | ForEach-Object { [string]$_ });state='available';source='windows-update-agent-configured-service'})
        }
        Coverage 'updates_available' 'partial' ('Applicable, non-hidden software updates from configured WUA service; result code='+$result.ResultCode)
    } catch { Coverage 'updates_available' 'error' $_.Exception.Message }
} else { Coverage 'updates_available' 'not_requested' 'Online applicability search requires explicit -check-windows-updates' }
@{schema_version=1;id='pending';asset_id='pending';collected_at=[DateTime]::UtcNow.ToString('o');collector='cerber-windows/1';os=$osInfo;coverage=@($coverage.ToArray());components=@($components.ToArray());updates=@($updates.ToArray())} | ConvertTo-Json -Depth 12 -Compress
