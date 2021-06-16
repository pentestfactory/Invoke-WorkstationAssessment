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
function Test-RegistryValue {

    param (

     [parameter(Mandatory=$true)]
     [ValidateNotNullOrEmpty()]$Path,

    [parameter(Mandatory=$true)]
     [ValidateNotNullOrEmpty()]$Value
    )

    try {

    Get-ItemProperty -Path $Path | Select-Object -ExpandProperty $Value -ErrorAction Stop | Out-Null
     return $true
     }

    catch {

    return $false

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



Write-Host '#########################' -BackgroundColor Black
Write-Host '## PowerShell Version  ##' -BackgroundColor Black
Write-Host '#########################' -BackgroundColor Black
Write-Host 'Checking the version used by default' -ForegroundColor Black -BackgroundColor White
Write-Host ' '
$PSVersionTable.PSVersion
Write-Host ' '
Write-Host ' '
Write-Host 'Checking if PowerShellv2 is installed' -ForegroundColor Black -BackgroundColor White
Get-WindowsOptionalFeature -Online | Where-Object {$_.FeatureName -match "PowerShellv2"}
Write-Host ' '
Write-Host ' '

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
             Write-Host 'Module Logging is enabled' -ForegroundColor Green
             Write-Host ' '
             Write-Host 'The following module names will be logged' -ForegroundColor Black -BackgroundColor White
             Write-Host ' '
             Get-ChildItem -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging\" | Format-Table Property
             Write-Host ' '
             Write-Host ' '
             Write-Host ' '

         }
         '0' 
         {
             Write-Host 'Module Logging is disabled - Explicitly deactivated' -ForegroundColor Red
             Write-Host ' '
             Write-Host ' '
             Write-Host ' '
         }
     }
}
else{
         Write-Host 'Module Logging is disabled - Not configured (Default)' -ForegroundColor Red
         Write-Host ' '
         Write-Host ' '
         Write-Host ' '
}




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
             Write-Host 'Script Block Logging is enabled' -ForegroundColor Green
             Write-Host ' '
             Write-Host ' '
             Write-Host ' '

         }
         '0' 
         {
             Write-Host 'Script Block Logging is disabled - Explicitly deactivated' -ForegroundColor Red
             Write-Host ' '
             Write-Host ' '
             Write-Host ' '
         }
     }
}
else{
         Write-Host 'Script Block Logging is disabled - Not configured (Default)' -ForegroundColor Red
         Write-Host ' '
         Write-Host ' '
         Write-Host ' '
}



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
             Write-Host 'Transcript Logging is enabled' -ForegroundColor Green
             Write-Host ' '
             Write-Host ' '

             ## Check Invocation Header
             if((Test-RegistryValue -Path $regPath -Value EnableInvocationHeader)){
                Write-Host 'Invocation Header is set' -ForegroundColor Green
                 ' '
             } else {
                Write-Host 'Invocation Header is not set' -ForegroundColor Red
                ' '
             }

             ## Output Directory
             if((Test-RegistryValue -Path $regPath -Value OutputDirectory)) {
                ' '
                'Output Directory is set to:'
                $outputDirectory=(Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription\" -Name "OutputDirectory").OutputDirectory
                if(([string]::IsNullOrEmpty($outputDirectory))){
                    Write-Host '(Default) Windows PowerShell will record transcript output to each users My Documents directory' -ForegroundColor Yellow
                    Write-Host ' '
                } else {
                    Write-Host $outputDirectory
                     Write-Host ' '
                }

             } else {
                Write-Host 'Output Directory is not set' -ForegroundColor Red
             }

         }
         '0' 
         {
             Write-Host 'Transcript Logging is disabled - Explicitly deactivated' -fore
             Write-Host ' '
             Write-Host ' '
             Write-Host ' '
         }
     }
}
else
{
         Write-Host 'Transcript Logging is disabled - Not configured (Default)' -ForegroundColor Red
         Write-Host ' '
         Write-Host ' '
         Write-Host ' '
}


Write-Host '#########################' -BackgroundColor Black
Write-Host '##    Language Mode    ##' -BackgroundColor Black
Write-Host '#########################' -BackgroundColor Black
Write-Host 'Checking if ConstrainedLanguage Mode is active' -ForegroundColor Black -BackgroundColor White
Switch($ExecutionContext.SessionState.LanguageMode)
{
        'FullLanguage' 
        {
            Write-Host 'Constrained Language Mode is not active' -ForegroundColor Red
            Write-Host ' '
            Write-Host ' '
            Write-Host ' '

        }
        'ConstrainedLanguage' 
        {
            Write-Host 'Constrained Language Mode is active' -ForegroundColor Green
            Write-Host ' '
            Write-Host ' '
            Write-Host ' '
        }
    }

Write-Host '#########################' -BackgroundColor Black
Write-Host '##       Sysmon        ##' -BackgroundColor Black
Write-Host '#########################' -BackgroundColor Black
Write-Host 'Checking if Sysmon is installed' -ForegroundColor Black -BackgroundColor White
Test-SysmonInstalled
Write-Host ' '
Write-Host ' '
Write-Host ' '

Write-Host '#########################' -BackgroundColor Black
Write-Host '##    LSA Protection   ##' -BackgroundColor Black
Write-Host '#########################' -BackgroundColor Black
Write-Host 'Checking if LSA Protection is enabled' -ForegroundColor Black -BackgroundColor White
## LSA Protection
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$regPathProperty = "RunAsPPL"

if((Test-RegistryValue -Path $regPath -Value $regPathProperty)){
    $check = Get-ItemProperty -Path $regPath | Select-Object -ExpandProperty $regPathProperty -ErrorAction silentlycontinue
    Switch($check)
    {
         '1' 
         {
             Write-Host 'LSA Protection is enabled' -ForegroundColor Green
             Write-Host ' '
             Write-Host ' '
             Write-Host ' '

         }
         '0' 
         {
             Write-Host 'LSA Protection is explicitly disabled' -ForegroundColor Red
             Write-Host ' '
             Write-Host ' '
             Write-Host ' '
         }
     }
 } else {
    Write-Host 'LSA Protection is not enabled' -ForegroundColor Red
    ' '
 }

## WDIGEST
# https://www.praetorian.com/blog/mitigating-mimikatz-wdigest-cleartext-credential-theft/
Write-Host '#########################' -BackgroundColor Black
Write-Host '##        WDigest      ##' -BackgroundColor Black
Write-Host '#########################' -BackgroundColor Black
Write-Host 'Checking if WDigest is enabled' -ForegroundColor Black -BackgroundColor White
$regPath = "HKLM:\\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
$regPathProperty = "UseLogonCredential"

if((Test-RegistryValue -Path $regPath -Value $regPathProperty)){
    $check = Get-ItemProperty -Path $regPath | Select-Object -ExpandProperty $regPathProperty -ErrorAction silentlycontinue
    Switch($check)
    {
         '1' 
         {
             Write-Host 'WDigest is enabled' -ForegroundColor Red
             Write-Host ' '
             Write-Host ' '
             Write-Host ' '

         }
         '0' 
         {
             Write-Host 'WDigest is not enabled' -ForegroundColor Green
             Write-Host ' '
             Write-Host ' '
             Write-Host ' '
         }
     }
 } else {
    Write-Host 'WDigest is not enabled' -ForegroundColor Green
    ' '
 }


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


Write-Host '#########################' -BackgroundColor Black
Write-Host '##     Device Guard    ##' -BackgroundColor Black
Write-Host '#########################' -BackgroundColor Black
Write-Host 'Checking if Device Guard is in use' -ForegroundColor Black -BackgroundColor White
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | Format-List

$SecurityProps = Get-CSDeviceGuardStatus
$SecurityProps.AvailableSecurityProperties



Write-Host '###########################' -BackgroundColor Black
Write-Host '##   Credential Guard    ##' -BackgroundColor Black
Write-Host '###########################' -BackgroundColor Black
Write-Host 'Checking if Credential Guard is in use' -ForegroundColor Black -BackgroundColor White
# https://github.com/MicrosoftDocs/windows-itpro-docs/blob/public/windows/security/identity-protection/credential-guard/credential-guard-manage.md
$DevGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
$check = $DevGuard.SecurityServicesConfigured -contains 1 -and $DevGuard.SecurityServicesRunning -contains 1

Switch($check)
{
        $true 
        {
            Write-Host 'Credential Guard is running' -ForegroundColor Green
            Write-Host ' '
            Write-Host ' '
            Write-Host ' '

        }
        $false 
        {
            Write-Host 'Credential Guard is not running' -ForegroundColor Red
            Write-Host ' '
            Write-Host ' '
            Write-Host ' '
        }
    }

Write-Host '#########################' -BackgroundColor Black
Write-Host '##   Windows Firewall  ##' -BackgroundColor Black
Write-Host '#########################' -BackgroundColor Black
Write-Host 'Checking Firewall State' -ForegroundColor Black -BackgroundColor White
$regkey = "HKLM:\System\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy"
New-Object -TypeName PSobject -Property @{
    Standard    = If ((Get-ItemProperty $regkey\StandardProfile).EnableFirewall -eq 1){"Enabled"}Else {"Disabled"}
    Domain      = If ((Get-ItemProperty $regkey\DomainProfile).EnableFirewall -eq 1){"Enabled"}Else {"Disabled"}
    Public      = If ((Get-ItemProperty $regkey\PublicProfile).EnableFirewall -eq 1){"Enabled"}Else {"Disabled"}
} | Format-Table
Write-Host 'Exporting Windows Firewall Rules to CSV-file'
Get-NetFirewallRule | Select-Object -Property Name, DisplayName, DisplayGroup, 
@{Name='Protocol';Expression={($PSItem | Get-NetFirewallPortFilter).Protocol}},
@{Name='LocalPort';Expression={($PSItem | Get-NetFirewallPortFilter).LocalPort}},
@{Name='RemotePort';Expression={($PSItem | Get-NetFirewallPortFilter).RemotePort}},
@{Name='RemoteAddress';Expression={($PSItem | Get-NetFirewallAddressFilter).RemoteAddress}}, Enabled, Profile, Direction, Action | 
Export-Csv -Path ".\CSV\Windows Firewall Rules.csv" -NoTypeInformation 


Write-Host '#########################' -BackgroundColor Black
Write-Host '##        LLMNR        ##' -BackgroundColor Black
Write-Host '#########################' -BackgroundColor Black
Write-Host 'Check if LLMNR is enabled' -ForegroundColor Black -BackgroundColor White
$regPath = "HKLM:\\Software\Policies\Microsoft\Windows NT\DNSClient"
$regPathProperty = "EnableMulticast"

if((Test-RegistryValue -Path $regPath -Value $regPathProperty)){
    $check = Get-ItemProperty -Path $regPath | Select-Object -ExpandProperty $regPathProperty -ErrorAction silentlycontinue
    Switch($check)
    {
         '1' 
         {
             Write-Host 'LLMNR is enabled' -ForegroundColor Red
             Write-Host ' '
             Write-Host ' '
             Write-Host ' '

         }
         '0' 
         {
             Write-Host 'LLMNR is disabled' -ForegroundColor Green
             Write-Host ' '
             Write-Host ' '
             Write-Host ' '
         }
     }
 } else {
    Write-Host 'LLMNR is disabled' -ForegroundColor Green
    ' '
 }

Write-Host '#########################' -BackgroundColor Black
Write-Host '##        NBNS         ##' -BackgroundColor Black
Write-Host '#########################' -BackgroundColor Black
Write-Host 'Check if NBNS is enabled' -ForegroundColor Black -BackgroundColor White
$regPath="HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
Get-ChildItem $regPath | foreach { get-ItemProperty -Path "$regPath\$($_.pschildname)" -Name NetbiosOptions} | Format-Table NetBiosOptions,@{Name='Interf
ace';Expression={$_.PSChildname}}

Write-Host '0 - Configuration via DHCP' -ForegroundColor Red
Write-Host '1 - Specifies that NetBIOS is enabled.' -ForegroundColor Red
Write-Host '2 - NetBIOS is disabled' -ForegroundColor Green
Write-Host ' '
Write-Host ' '
Write-Host ' '
# Mitigation:
# $regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
# Get-ChildItem $regkey |foreach { Set-ItemProperty -Path "$regkey\$($_.pschildname)" -Name NetbiosOptions -Value 2 -Verbose}
# http://woshub.com/how-to-disable-netbios-over-tcpip-and-llmnr-using-gpo/#h2_4

# Windows Defender
# https://www.windowscentral.com/how-manage-microsoft-defender-antivirus-powershell-windows-10
Write-Host '#########################' -BackgroundColor Black
Write-Host '#    Windows Defender  ##' -BackgroundColor Black
Write-Host '#########################' -BackgroundColor Black
$defenderPreferences = Get-MpPreference

if(($defenderDetails.RealTimeProtectionEnabled)){
    Write-Host 'Defender is active' -ForegroundColor Green
    ' '
    ' '
 } else {
    Write-Host 'Defender is not active' -ForegroundColor Red
    Write-Host ' '
    Write-Host ' '
 }


Write-Host '##########################' -BackgroundColor Black
Write-Host '##  Installed Software  ##' -BackgroundColor Black
Write-Host '##########################' -BackgroundColor Black
Write-Host 'Getting a list of installed Software:' -ForegroundColor Black -BackgroundColor White
Get-WMIObject -Query "SELECT * FROM Win32_Product" | Select-Object Name,Version,Vendor,InstallLocation,InstallDate | format-table
Write-Host ' '
Write-Host ' '
Write-Host 'Exporting installed software to CSV-File'
Get-WMIObject -Query "SELECT * FROM Win32_Product" | Select-Object Name,Version,Vendor,InstallLocation,InstallDate | Export-Csv -Path ".\CSV\Installed Software.csv" -NoTypeInformation 



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
    Where-Object { $_.LocalAddress -eq "0.0.0.0" -and $_.State -eq "Listen" } |
    Select-Object LocalAddress,
        LocalPort,
        @{Name="PID";         Expression={ $_.OwningProcess }},
        @{Name="UserName";    Expression={ $Processes[[int]$_.OwningProcess].UserName }},
        @{Name="ProcessName"; Expression={ $Processes[[int]$_.OwningProcess].ProcessName }}, 
        @{Name="Path"; Expression={ $Processes[[int]$_.OwningProcess].Path }} |
    Sort-Object -Property LocalPort, UserName |
    Format-Table -AutoSize

    Get-NetTCPConnection | 
    Where-Object { $_.LocalAddress -eq "0.0.0.0" -and $_.State -eq "Listen" } |
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
    Where-Object { $_.LocalAddress -eq "0.0.0.0" } |
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
        Where-Object { $_.LocalAddress -eq "0.0.0.0" } |
        Select-Object LocalAddress,
            LocalPort,
            @{Name="PID";         Expression={ $_.OwningProcess }},
            @{Name="UserName";    Expression={ $Processes[[int]$_.OwningProcess].UserName }},
            @{Name="ProcessName"; Expression={ $Processes[[int]$_.OwningProcess].ProcessName }}, 
            @{Name="Path"; Expression={ $Processes[[int]$_.OwningProcess].Path }} |
        Sort-Object -Property LocalPort, UserName | Export-Csv -Path ".\CSV\Network Services - UDP.csv" -NoTypeInformation 


Write-Host '###################' -BackgroundColor Black
Write-Host '##  Local Users  ##' -BackgroundColor Black
Write-Host '###################' -BackgroundColor Black
Write-Host "Local Users and their group memberships" -ForegroundColor Black -BackgroundColor White

Get-LocalUser | 
    ForEach-Object { 
        $user = $_
        return [PSCustomObject]@{ 
            "User"   = $user.Name
            "Enabled" = $user.Enabled
            "LastLogon" = $user.LastLogon
            "Description" = $user.Description
            "SID" = $user.SID
            "PasswordLastSet" = $user.PasswordLastSet
            "Groups" = Get-LocalGroup | Where-Object {  $user.SID -in ($_ | Get-LocalGroupMember | Select-Object -ExpandProperty "SID") } | Select-Object -ExpandProperty "Name"
            "FullName"  = $user.FullName
        } 
    } | Format-Table -Wrap -AutoSize

    Get-LocalUser |
    ForEach-Object {
        $user = $_
        return [PSCustomObject]@{
            "User"   = $user.Name
            "Enabled" = $user.Enabled
            "LastLogon" = $user.LastLogon
            "Description" = $user.Description
            "SID" = $user.SID
            "PasswordLastSet" = $user.PasswordLastSet
            "Groups" = (Get-LocalGroup | Where-Object {  $user.SID -in ($_ | Get-LocalGroupMember | Select-Object -ExpandProperty "SID") } | Select-Object -ExpandProperty "Name" | Out-String).Trim()
            "FullName"  = $user.FullName
        }
    } | Export-Csv -Path ".\CSV\Users.csv" -NoTypeInformation 


Write-Host '###################' -BackgroundColor Black
Write-Host '##   Processes   ##' -BackgroundColor Black
Write-Host '###################' -BackgroundColor Black
Write-Host "Running processes" -ForegroundColor Black -BackgroundColor White
$Results = Get-ProcessInfo
$Results | Format-Table Name, Owner, ID, Path, CommandLine -auto 
Get-ProcessInfo | Select-Object Name, Owner, ID, Path, CommandLine | Export-Csv -Path ".\CSV\Processes.csv" -NoTypeInformation 


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
    Write-Host 'Secure Boot is disabled' -ForegroundColor Red
    $secBootError=$true
}

if ($securebootUEFI) 
{
	Write-Host 'Secure Boot is enabled' -ForegroundColor Green
    Get-SecureBootPolicy
}
else
{
    if($secBootError -eq $false){
        Write-Host 'Secure Boot is disabled' -ForegroundColor Red
    }
}


Write-Host '#################################' -BackgroundColor Black
Write-Host '##    Explicit Logon Events    ##' -BackgroundColor Black
Write-Host '#################################' -BackgroundColor Black
#Get-ExplicitLogonEvents | Format-Table


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
	Write-Host 'SMBv1 is enabled' -ForegroundColor Red
    Write-Host ' '
    Write-Host ' '
    Get-WindowsOptionalFeature -Online -FeatureName smb1protocol
}
else
{
        Write-Host 'SMBv1 is disabled' -ForegroundColor Green
        Write-Host ' '
        Write-Host ' '
}

Write-Host '#################################' -BackgroundColor Black
Write-Host '##         SMB-Signing         ##' -BackgroundColor Black
Write-Host '#################################' -BackgroundColor Black

Write-Host 'Check if SMB-Signing is enabled (Client)' -ForegroundColor Black -BackgroundColor White
$regPath = "HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters"
$regPathProperty = "EnableSecuritySignature"

if((Test-RegistryValue -Path $regPath -Value $regPathProperty)){
    $check = Get-ItemProperty -Path $regPath | Select-Object -ExpandProperty $regPathProperty -ErrorAction silentlycontinue
    Switch($check)
    {
         '1' 
         {
             Write-Host 'SMB-Signing (Client) is enabled' -ForegroundColor Green

         }
         '0' 
         {
             Write-Host 'SMB-Signing (Client) is disabled' -ForegroundColor Red
         }
     }
 } else {
    Write-Host 'SMB-Signing (Client) is disabled' -ForegroundColor Red
 }

Write-Host 'Check if SMB-Signing is enforced (Client)' -ForegroundColor Black -BackgroundColor White
$regPath = "HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters"
$regPathProperty = "RequireSecuritySignature"

if((Test-RegistryValue -Path $regPath -Value $regPathProperty)){
    $check = Get-ItemProperty -Path $regPath | Select-Object -ExpandProperty $regPathProperty -ErrorAction silentlycontinue
    Switch($check)
    {
         '1' 
         {
             Write-Host 'SMB-Signing (Client) is enforced' -ForegroundColor Green
             Write-Host ' '
             Write-Host ' '

         }
         '0' 
         {
             Write-Host 'SMB-Signing (Client) is not enforced and can be downgraded' -ForegroundColor Red
             Write-Host ' '
             Write-Host ' '
         }
     }
 } else {
    Write-Host 'SMB-Signing (Client) is not enforced and can be downgraded' -ForegroundColor Red
    ' '
 }

 Write-Host 'Check if SMB-Signing is enabled (server)' -ForegroundColor Black -BackgroundColor White
$regPath = "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters"
$regPathProperty = "EnableSecuritySignature"

if((Test-RegistryValue -Path $regPath -Value $regPathProperty)){
    $check = Get-ItemProperty -Path $regPath | Select-Object -ExpandProperty $regPathProperty -ErrorAction silentlycontinue
    Switch($check)
    {
         '1' 
         {
             Write-Host 'SMB-Signing (server) is enabled' -ForegroundColor Green

         }
         '0' 
         {
             Write-Host 'SMB-Signing (server) is disabled' -ForegroundColor Red
         }
     }
 } else {
    Write-Host 'SMB-Signing (server) is disabled' -ForegroundColor Red
    ' '
 }

Write-Host 'Check if SMB-Signing is enforced (server)' -ForegroundColor Black -BackgroundColor White
$regPath = "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters"
$regPathProperty = "RequireSecuritySignature"

if((Test-RegistryValue -Path $regPath -Value $regPathProperty)){
    $check = Get-ItemProperty -Path $regPath | Select-Object -ExpandProperty $regPathProperty -ErrorAction silentlycontinue
    Switch($check)
    {
         '1' 
         {
             Write-Host 'SMB-Signing (server) is enforced' -ForegroundColor Green
             Write-Host ' '
             Write-Host ' '

         }
         '0' 
         {
             Write-Host 'SMB-Signing (server) is not enforced and can be downgraded' -ForegroundColor Red
             Write-Host ' '
             Write-Host ' '
         }
     }
 } else {
    Write-Host 'SMB-Signing (server) is not enforced and can be downgraded' -ForegroundColor Red
    ' '
 }


 Write-Host '#################################' -BackgroundColor Black
 Write-Host '##   User Rights Assignment    ##' -BackgroundColor Black
 Write-Host '#################################' -BackgroundColor Black
 Write-Host 'Enumerating User Rights Assignment' -ForegroundColor Black -BackgroundColor White
 Get-UserRightsAssignment | Sort-Object -Property PrivilegeName | Format-Table 
 Get-UserRightsAssignment | Sort-Object -Property PrivilegeName | Export-Csv -Path ".\CSV\User Rights Assignment.csv" -NoTypeInformation

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

Write-Host '#################################' -BackgroundColor Black
Write-Host '##     ScheduledTasks          ##' -BackgroundColor Black
Write-Host '#################################' -BackgroundColor Black
Write-Host 'Enumerating ScheduledTasks (filtered - non Microsoft)' -ForegroundColor Black -BackgroundColor White
Get-ScheduledTasks | Format-Table Name, Enabled, UserId, LastRunTime, NextRunTime, Status, Action, Arguments
Get-ScheduledTasks | Export-Csv -Path ".\CSV\Scheduled Tasks.csv" -NoTypeInformation

Write-Host '#################################' -BackgroundColor Black
Write-Host '##          Services           ##' -BackgroundColor Black
Write-Host '#################################' -BackgroundColor Black
Write-Host 'Enumerating running services' -ForegroundColor Black -BackgroundColor White
Get-WmiObject win32_service | ? {($_.state -match 'running')} | Sort-Object DisplayName | Format-Table Name, DisplayName, StartName, state, ProcessID -AutoSize -Wrap
Write-Host 'Enumerating stopped services' -ForegroundColor Black -BackgroundColor White
Get-WmiObject win32_service | ? {-not ($_.state -match 'running')} | Sort-Object DisplayName | Format-Table Name, DisplayName, StartName, state, ProcessID -AutoSize -Wrap
Get-WmiObject win32_service | Sort-Object DisplayName | Select-Object Name, DisplayName, StartName, state, ProcessID | Export-Csv -Path ".\CSV\Windows Services.csv" -NoTypeInformation
# TODO
# Registry Auditing for Credential Theft - https://medium.com/threatpunter/detecting-attempts-to-steal-passwords-from-the-registry-7512674487f8
# 
Write-Host '#################################' -BackgroundColor Black
Write-Host '##       CIS-Hardening         ##' -BackgroundColor Black
Write-Host '#################################' -BackgroundColor Black
Invoke-WebRequest -Uri "https://github.com/scipag/HardeningKitty/archive/refs/heads/master.zip" -OutFile ".\HardeningKitty.zip"
Expand-Archive -Path ".\HardeningKitty.zip"
Import-Module ".\HardeningKitty\HardeningKitty-master\Invoke-HardeningKitty.ps1"
Invoke-HardeningKitty -FileFindingList ".\HardeningKitty\HardeningKitty-master\lists\finding_list_cis_microsoft_windows_10_enterprise_20h2_machine.csv" -SkipMachineInformation -Report "Audit" -ReportFile ".\CSV\Hardening CIS.csv"

