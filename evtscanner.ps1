param ([Parameter(Mandatory=$true)]$ip)

# Get current timestamp when the log was analyzed
$getdate   = Get-Date -UFormat "%Y %b %d %R:%S"
$timestamp = $getdate.replace(".",":")

# Syslog parameters 
$UdpClient = New-Object System.Net.Sockets.UdpClient
$adr       = $ip
$Port      = "514"

# Syslog + message function
Function Send-Syslog {
    param(
        [Parameter()][string]$Parameter1,
        [Parameter()][string]$Parameter2,
        [Parameter()][string]$Parameter3,
        [Parameter()][string]$Parameter4,
        [Parameter()][string]$Parameter5,
        [Parameter()][string]$Parameter6,
        [Parameter()][string]$Parameter7
    )

    # The actual message format with parameters
    $msg       = "$time WinEvtLog: $channel`: EVENT-ID($id)`: $provider`: COMPUTER: $computer`: $message CollectTime: $timestamp"
    $bytearray = $([System.Text.Encoding])::ASCII.GetBytes($msg)
    $UdpClient.Connect($adr,$Port)
    $UdpClient.Send($bytearray, $bytearray.length) | out-null
}

# Parameters for Send-Syslog function. Needed for messages
$Parameters = @{
    Parameter1 = $time
    Parameter2 = $channel
    Parameter3 = $id
    Parameter4 = $provider
    Parameter5 = $computer
    Parameter6 = $message
    Parameter7 = $timestamp
}

#  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# |                                                                           |
# - Process create events - Sysmon event id 1 / Windows process creation 4688 -
# |                                                                           |
#  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

# Different suspicious or malicious command line parameters
$CommandLine = @( 
    ' -NoP ',                                      # Often used in malicious PowerShell commands 
    ' -W Hidden ',                                 # Often used in malicious PowerShell commands
    ' -decode ',                                   # Used with certutil
    ' /decode ',                                   # Used with certutil 
    ' -e(?s).*JAB',                                # PowerShell encoded commands
    ' -e(?s).*SUVYI',                              # PowerShell encoded commands
    ' -e(?s).*SQBFAFgA',                           # PowerShell encoded commands
    ' -e(?s).*aWV4I',                              # PowerShell encoded commands
    ' -e(?s).*IAB',                                # PowerShell encoded commands
    ' -e(?s).*PAA',                                # PowerShell encoded commands
    ' -e(?s).*aQBlAHgA',                           # PowerShell encoded commands
    'vssadmin delete shadows',                     # Ransomware
    'reg SAVE HKLM\\SAM',                          # save registry SAM - syskey extraction
    ' -ma ',                                       # ProcDump
    'Microsoft\\Windows\\CurrentVersion\\Run',     # Run key in command line - often in combination with REG ADD
    '.downloadstring\(',                           # PowerShell download command
    '.downloadfile\(',                             # PowerShell download command
    ' /ticket:',                                   # Rubeus
    ' sekurlsa',                                   # Mimikatz
    ' p::d',                                       # Mimikatz 
    ';iex\(',                                      # PowerShell IEX
    'schtasks(?s).*/create(?s).*AppData',          # Scheduled task creation pointing to AppData
    ' comsvcs.dll,MiniDump',                       # Process dumping method apart from procdump
    ' comsvcs.dll,#24',                            # Process dumping method apart from procdump
    'Add-MpPreference(?s).*ExclusionPath',         # Defender exclusion
    'Add-MpPreference(?s).*ExclusionExtension',    # Defender exclusion
    'Add-MpPreference(?s).*ExclusionProcess',      # Defender exclusion
    'DisableBehaviorMonitoring $true',             # Defender disable
    'DisableRunTimeMonitoring $true',              # Defender disable
    'sc(?s).*stop(?s).*WinDefend',                 # Defender disable
    'sc(?s).*config(?s).*WinDefend(?s).*disabled', # Defender disable
    'FromBase64String\(',                          # Suspicious FromBase64String expressions
    'cmd.exe /Q /c(?s).*\\\\127.0.0.1\\',          # wmiexec.py https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py#L287
    'cmd.exe /C(?s).*\\\\Temp\\'                   # atexec.py  https://github.com/SecureAuthCorp/impacket/blob/master/examples/atexec.py#L122
)

# Office Dropper Detection
$ParentImage = @(
    '\\WINWORD.EXE',
    '\\EXCEL.EXE',
    '\\POWERPNT.exe',
    '\\MSPUB.exe',
    '\\VISIO.exe',
    '\\OUTLOOK.EXE'
)

$Image = @(
    '\\cmd.exe',
    '\\powershell.exe',
    '\\wscript.exe',
    '\\cscript.exe',
    '\\schtasks.exe',
    '\\scrcons.exe',
    '\\regsvr32.exe',
    '\\hh.exe',
    '\\wmic.exe',
    '\\mshta.exe',
    '\\msiexec.exe',
    '\\forfiles.exe',
    '\\AppData\\'
)

# Webshells
$WImage = @(
    '\\apache(?s).*',
    '\\tomcat(?s).*',
    '\\w3wp.exe',
    '\\php-cgi.exe',
    '\\nginx.exe',
    '\\httpd.exe'
)

$WCommandLine = @(
    'whoami',
    'net user ',
    'ping -n ',
    'systeminfo',
    '&cd&echo',
    'cd /d '      # https://www.computerhope.com/cdhlp.htm
)

# Sysmon process create event id 1
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Sysmon/Operational'; Id='1'} | Foreach-Object {
    $entry            = [xml]$_.ToXml()
    $provider         = $entry.Event.System.Provider.Name
    $id               = $entry.Event.System.EventID
    $time             = $entry.Event.System.TimeCreated.SystemTime
    $channel          = $entry.Event.System.Channel
    $computer         = $entry.Event.System.Computer
    $message          = $_."Message" -replace "\r\n"," " -replace "\s"," "
    $xmlcmdline       = $entry.SelectSingleNode("//*[@Name='CommandLine']")."#text"
    $xmlparentcmdline = $entry.SelectSingleNode("//*[@Name='ParentCommandLine']")."#text"
    $xmlparentimage   = $entry.SelectSingleNode("//*[@Name='ParentImage']")."#text"
    $xmlimage         = $entry.SelectSingleNode("//*[@Name='Image']")."#text"
    $xmluser          = $entry.SelectSingleNode("//*[@Name='User']")."#text"
        
        # Different suspicious or malicious command line parameters
        foreach ($c in $commandline) {
            if ($xmlcmdline -match ($c) -or $xmlparentcmdline -match ($c)) {            
                Send-Syslog @Parameters
            }
        }
        
        # Office dropper detection
        foreach ($p in $ParentImage) {
            foreach ($i in $image) {
                if($xmlparentimage -match ($p) -and $xmlimage -match ($i)) {
                    Send-Syslog @Parameters
                }
            }
        }

        # Webshells
        foreach ($w in $wimage) {
            foreach ($wc in $wcommandline) {
                if ($xmlimage -match ($w) -and $xmlcmdline -match ($wc)) {
                    Send-Syslog @Parameters
                }
            }
        }

        # Whoami as System
        if($xmluser -match 'AUTHORITY\\SYSTEM' -and $xmlimage -match '\\whoami.exe') {
            Send-Syslog @Parameters
        }
}

# Windows process creation event id 4688
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4688'} | Foreach-Object {
    $entry =          [xml]$_.ToXml()
    $provider =       $entry.Event.System.Provider.Name
    $id =             $entry.Event.System.EventID
    $time =           $entry.Event.System.TimeCreated.SystemTime
    $channel =        $entry.Event.System.Channel
    $computer =       $entry.Event.System.Computer
    $message =        $_."Message" -replace "\r\n"," " -replace "\s"," "
    $xmlcmdline =     $entry.SelectSingleNode("//*[@Name='CommandLine']")."#text"
    $xmlparentimage = $entry.SelectSingleNode("//*[@Name='ParentProcessName']")."#text"
    $xmlimage =       $entry.SelectSingleNode("//*[@Name='NewProcessName']")."#text"
    $xmluser =        $entry.SelectSingleNode("//*[@Name='SubjectUserSid']")."#text"

        # Different suspicious or malicious command line parameters
        foreach ($c in $commandline) {
            if ($xmlcmdline -match ($c)) {            
                Send-Syslog @Parameters
            }
        }
        
        # Office dropper detection
        foreach ($p in $ParentImage) {
            foreach ($i in $image) {
                if($xmlparentimage -match ($p) -and $xmlimage -match ($i)) {
                    Send-Syslog @Parameters
                }
            }
        }

        # Webshells
        foreach ($w in $wimage) {
            foreach ($wc in $wcommandline) {
                if ($xmlimage -match ($w) -and $xmlcmdline -match ($wc)) {
                    Send-Syslog @Parameters
                }
            }
        }

        # Whoami as System
        if($xmluser -eq 'S-1-5-18' -and $xmlimage -match '\\whoami.exe') {
            Send-Syslog @Parameters
        }
}

#  - - - - - - - - - - - - - - -
# |                             |
# - Sysmon file create event 11 -
# |                             |
#  - - - - - - - - - - - - - - -

$TargetFile = @(
    '.dmp',             # Dump process memory
    'Desktop\\how',     # Ransomware
    'Desktop\\decrypt', # Ransomware
    'bloodhound.bin'    # By default Bloodhound drops this file to disk
)

Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Sysmon/Operational'; Id='11'} | Foreach-Object {
    $entry =          [xml]$_.ToXml()
    $provider =       $entry.Event.System.Provider.Name
    $id =             $entry.Event.System.EventID
    $time =           $entry.Event.System.TimeCreated.SystemTime
    $channel =        $entry.Event.System.Channel
    $computer =       $entry.Event.System.Computer
    $message =        $_."Message" -replace "\r\n"," " -replace "\s"," "
    $xmltarfilename = $entry.SelectSingleNode("//*[@Name='TargetFilename']")."#text"

        # Targetfile
        foreach ($t in $TargetFile) {
            if ($xmltarfilename -match ($t)) {
                Send-Syslog @Parameters
            }
        }
}

#  - - - - - - - - - - - - - - - - - -
# |                                   |
# - Sysmon registry events 12 and 13  -
# |                                   |
#  - - - - - - - - - - - - - - - - - -

$TargetObject = @(
    'UserInitMprLogonScript',                           # Persistence
    '\\CurrentVersion\\Image File Execution Options\\', # Persistence
    '\\Microsoft\\Windows\\CurrentVersion\\Run\\',      # Persistence
    '\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\'   # Persistence
)

$Details = @(
    'AppData',
    '\\Users\\Public\\',
    '\\Temp\\',
    'powershell',
    'wscript',
    'cscript'
)

Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Sysmon/Operational'; Id=12,13} | Foreach-Object {
    $entry =        [xml]$_.ToXml()
    $provider =     $entry.Event.System.Provider.Name
    $id =           $entry.Event.System.EventID
    $time =         $entry.Event.System.TimeCreated.SystemTime
    $channel =      $entry.Event.System.Channel
    $computer =     $entry.Event.System.Computer
    $message =      $_."Message" -replace "\r\n"," " -replace "\s"," "
    $xmltarobject = $entry.SelectSingleNode("//*[@Name='TargetObject']")."#text"
    $xmldetails =   $entry.SelectSingleNode("//*[@Name='Details']")."#text"

        # TargetObject
        foreach ($to in $targetobject) {
            if ($xmltarobject -match ($to)) {
                Send-Syslog @Parameters
            }
        }

        # Details
        foreach ($d in $details) {
            if ($xmldetails -match ($d)) {
                Send-Syslog @Parameters
            }
        }
}

#  - - - - - - - - - - - - - - - 
# |                             |
# - Sysmon Named Pipe events 17 -
# |                             |
#  - - - - - - - - - - - - - - - 

$PipeNames = @(
    'postex',                               # Cobalt Strike Pipe Name                     
    'status_',                              # Cobalt Strike Pipe Name
    'msagent_',                             # Cobalt Strike Pipe Name
    'lsadump',                              # Password or Credential Dumpers
    'cachedump',                            # Password or Credential Dumpers
    'wceservicepipe',                       # Password or Credential Dumpers
    'isapi',                                # Malware named pipes
    'sdlrpc',                               # Malware named pipes
    'ahexec',                               # Malware named pipes
    'winsession',                           # Malware named pipes
    'lsassw',                               # Malware named pipes
    '46a676ab7f179e511e30dd2dc41bd388',     # Malware named pipes
    '9f81f59bc58452127884ce513865ed20',     # Malware named pipes
    'e710f28d59aa529d6792ca6ff0ca1b34',     # Malware named pipes
    'rpchlp_3',                             # Malware named pipes
    'NamePipe_MoreWindows',                 # Malware named pipes
    'pcheap_reuse',                         # Malware named pipes
    'gruntsvc',                             # Malware named pipes
    '583da945-62af-10e8-4902-a8f205c72b2e', # Malware named pipes
    'bizkaz',                               # Malware named pipes
    'svcctl',                               # Malware named pipes
    'Posh',                                 # Malware named pipes
    'jaccdpqnvbrrxlaf',                     # Malware named pipes
    'csexecsvc',                            # Malware named pipes
    'paexec',                               # Remote Command Execution Tools
    'remcom',                               # Remote Command Execution Tools
    'csexec'                                # Remote Command Execution Tools
)

Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Sysmon/Operational'; Id=17} | Foreach-Object {
    $entry =        [xml]$_.ToXml()
    $provider =     $entry.Event.System.Provider.Name
    $id =           $entry.Event.System.EventID
    $time =         $entry.Event.System.TimeCreated.SystemTime
    $channel =      $entry.Event.System.Channel
    $computer =     $entry.Event.System.Computer
    $message =      $_."Message" -replace "\r\n"," " -replace "\s"," "
    $xmlpipename =  $entry.SelectSingleNode("//*[@Name='PipeName']")."#text"

        foreach ($p in $PipeNames) {
            if ($xmlpipename -match ($p)) {
                Send-Syslog @Parameters
            }
        }  
}

#  - - - - - - - - - - - - - - - - - - - - - - - - - -
# |                                                   |
# - System events (7045) - Malicious service installs -
# |                                                   |
#  - - - - - - - - - - - - - - - - - - - - - - - - - -

$ServiceName = @(
    'WCESERVICE',  # PW Dumping         https://attack.mitre.org/software/S0005/
    'WCE SERVICE', # PW Dumping         https://attack.mitre.org/software/S0005/
    'winexesvc',   # PsExec alternative https://attack.mitre.org/software/S0191/
    'DumpSvc',     # PW Dumping
    'pwdump',      # PW Dumping         https://attack.mitre.org/software/S0006/
    'gsecdump',    # PW Dumping         https://attack.mitre.org/software/S0008/
    'cachedump'    # PW Dumping         https://attack.mitre.org/software/S0119/
)

$ServiceFilename = @(
    '\\\\.\\pipe',    # Possible get-system usage. Named pipe service - https://blog.cobaltstrike.com/2014/04/02/what-happens-when-i-type-getsystem/
    '\\\\127.0.0.1\\' # Detects smbexec from Impacket framework       - https://neil-fox.github.io/Impacket-usage-&-detection/
)

Get-WinEvent -FilterHashtable @{ LogName='System'; Id='7045'} | Foreach-Object {
    $entry =              [xml]$_.ToXml()
    $provider =           $entry.Event.System.Provider.Name
    $id =                 $entry.Event.System.EventID.Qualifiers
    $time =               $entry.Event.System.TimeCreated.SystemTime
    $channel =            $entry.Event.System.Channel
    $computer =           $entry.Event.System.Computer
    $message =            $_."Message" -replace "\r\n"," " -replace "\s"," "
    $xmlservicename =     $entry.SelectSingleNode("//*[@Name='ServiceName']")."#text"
    $xmlserviceFilename = $entry.SelectSingleNode("//*[@Name='ImagePath']")."#text"

        foreach ($s in $ServiceName) {
            if ($xmlservicename -match ($s)) {
                Send-Syslog @Parameters
            }
        }

        foreach ($sf in $ServiceFilename) {
            if ($xmlservicefilename -match ($sf)) {
                Send-Syslog @Parameters
            }
        }
}

#  - - - - - - - - - - - - - - - - - - - - -
# |                                         |
# - Windows Defender event id 1116 and 1117 -
# |                                         |
#  - - - - - - - - - - - - - - - - - - - - -

# 1116 Windows Defender Antivirus has detected malware or other potentially unwanted software
# 1117 Windows Defender Antivirus has taken action to protect this machine from malware or other potentially unwanted software.

Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Windows Defender/Operational'; Id=1116,1117} | Foreach-Object {
    $entry =          [xml]$_.ToXml()
    $provider =       $entry.Event.System.Provider.Name
    $id =             $entry.Event.System.EventID.Qualifiers
    $time =           $entry.Event.System.TimeCreated.SystemTime
    $channel =        $entry.Event.System.Channel
    $computer =       $entry.Event.System.Computer
    $message =        $_."Message" -replace "\r\n"," " -replace "\s"," "
    $xmlservicename = $entry.SelectSingleNode("//*[@Name='ServiceName']")."#text"
    
    Send-Syslog @Parameters
}
