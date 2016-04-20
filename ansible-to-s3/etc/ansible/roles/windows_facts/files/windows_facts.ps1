#!powershell
# <license>

# WANT_JSON
# POWERSHELL_COMMON

# code goes here, reading in stdin as JSON and outputting JSON

$UpdImp = $UpdOpt = 0
$Session = New-Object -ComObject "Microsoft.Update.Session"
$Updates = $Session.CreateUpdateSearcher().Search(("IsHidden=0 and IsInstalled=0 and Type='Software'")).Updates
foreach ($upd in $Updates) { if ($upd.AutoSelectOnWebSites) { $UpdImp++ } else { $UpdOpt++ } }
Write-Host $UpdOpt
Write-Host $UpdImp
