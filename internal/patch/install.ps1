# SPDX-License-Identifier: Apache-2.0
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false)
$items=New-Object System.Collections.ArrayList
$reboot='unknown'
try {
 $info=New-Object -ComObject Microsoft.Update.SystemInfo
 $reboot=if($info.RebootRequired){'yes'}else{'no'}
 $session=New-Object -ComObject Microsoft.Update.Session
 $session.ClientApplicationID='Cerber managed updates (no automatic reboot)'
 $searcher=$session.CreateUpdateSearcher()
 $searcher.Online=$true
 $search=$searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
 if([int]$search.ResultCode -ne 2){throw 'Applicability search incomplete'}
 foreach($u in $q.updates){
  $status='failed';$code='not_applicable'
  try {
   $update=$null
   for($i=0;$i -lt $search.Updates.Count;$i++){
    $v=$search.Updates.Item($i)
    if([string]$v.Identity.UpdateID -eq $u.id -and [int]$v.Identity.RevisionNumber -eq [int]$u.revision){$update=$v;break}
   }
   if($null -eq $update){$code='candidate_changed';throw 'candidate_changed'}
   if($update.InstallationBehavior.CanRequestUserInput){$code='interactive_update_rejected';throw 'interactive_update_rejected'}
   if(-not $update.EulaAccepted){$code='eula_acceptance_required_outside_cerber';throw 'eula_acceptance_required_outside_cerber'}
   if($q.mode -eq 'preview'){$status='ready';$code='applicable'}else{
    $collection=New-Object -ComObject Microsoft.Update.UpdateColl
    [void]$collection.Add($update)
    $downloader=$session.CreateUpdateDownloader();$downloader.Updates=$collection
    $download=$downloader.Download()
    if([int]$download.ResultCode -ne 2 -or -not $update.IsDownloaded){$code='download_failed';throw 'download_failed'}
    $installer=$session.CreateUpdateInstaller();$installer.Updates=$collection
    $installer.AllowSourcePrompts=$false;$installer.ForceQuiet=$true
    if($installer.RebootRequiredBeforeInstallation){$reboot='yes';$code='reboot_required_before_install';throw 'reboot_required_before_install'}
    if([DateTimeOffset]::UtcNow -ge [DateTimeOffset]::Parse([string]$q.expires_at)){$code='authorization_expired';throw 'authorization_expired'}
    $status='unknown';$code='installation_started'
    $installed=$installer.Install()
    $one=$installed.GetUpdateResult(0)
    if($installed.RebootRequired -or $one.RebootRequired){$reboot='yes'}
    $code='wua_result_'+[int]$one.ResultCode+'_hresult_'+[int]$one.HResult
    if([int]$one.ResultCode -eq 2){$status='installed'}else{$status='failed'}
   }
  }catch{if($status -ne 'unknown'){$status='failed'};$code=if($code -eq 'installation_started'){'install_interrupted_reconcile_wua_history'}else{$code}}
  [void]$items.Add(@{id=[string]$u.id;status=$status;code=$code})
 }
 $info=New-Object -ComObject Microsoft.Update.SystemInfo
 if($info.RebootRequired){$reboot='yes'}
}catch{
 if($reboot -ne 'yes'){$reboot='unknown'}
 foreach($u in $q.updates){if(-not @($items | Where-Object {$_.id -eq $u.id}).Count){[void]$items.Add(@{id=[string]$u.id;status='failed';code='wua_unavailable'})}}
}
$good=@($items | Where-Object {$_.status -in @('ready','installed','already_installed')}).Count
$status=if(@($items|Where-Object {$_.status -eq 'unknown'}).Count){'unknown'}elseif($good -eq $q.updates.Count){'succeeded'}elseif($good -gt 0){'partial'}else{'failed'}
@{id=[string]$q.id;status=$status;reboot_required=$reboot;items=@($items.ToArray());detail='WUA configured service; Cerber never requests restart'} | ConvertTo-Json -Depth 8 -Compress
