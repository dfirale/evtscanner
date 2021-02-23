param (
    $ip
 )

# Get current timestamp when the log was analyzed
$getdate = Get-Date -UFormat "%Y %b %d %R:%S"
$timestamp = $getdate.replace(".",":")

# Syslog parameters. 
$UdpClient = New-Object System.Net.Sockets.UdpClient
$adr = $ip
$Port = "514"

# Predefine Syslog-function
Function Send-Syslog ($msg) {
    $bytearray = $([System.Text.Encoding])::ASCII.GetBytes($msg)
    $UdpClient.Connect($adr,$Port)
    $UdpClient.Send($bytearray, $bytearray.length) | out-null
}

#  ____                                                 ____                          __             
# /\  _`\                                              /\  _`\                       /\ \__          
# \ \ \L\ \_ __   ___     ___     __    ____    ____   \ \ \/\_\  _ __    __     __  \ \ ,_\    __   
#  \ \ ,__/\`'__\/ __`\  /'___\ /'__`\ /',__\  /',__\   \ \ \/_/_/\`'__\/'__`\ /'__`\ \ \ \/  /'__`\ 
#   \ \ \/\ \ \//\ \L\ \/\ \__//\  __//\__, `\/\__, `\   \ \ \L\ \ \ \//\  __//\ \L\.\_\ \ \_/\  __/ 
#    \ \_\ \ \_\\ \____/\ \____\ \____\/\____/\/\____/    \ \____/\ \_\\ \____\ \__/.\_\\ \__\ \____\
#     \/_/  \/_/ \/___/  \/____/\/____/\/___/  \/___/      \/___/  \/_/ \/____/\/__/\/_/ \/__/\/____/
#                                                                                                   
#       Sysmon event id 1 / Windows process creation 4688

# Different suspicious or malicious command line parameters
# https://github.com/Neo23x0/sigma/blob/master/other/godmode_sigma_rule.yml

$CommandLine = @( 
    ' -NoP ',  # Often used in malicious PowerShell commands 
    ' -W Hidden ',  # Often used in malicious PowerShell commands
    ' -decode ',  # Used with certutil
    ' /decode ',  # Used with certutil 
    ' -e(?s).*JAB',  # PowerShell encoded commands
    ' -e(?s).*SUVYI',  # PowerShell encoded commands
    ' -e(?s).*SQBFAFgA',  # PowerShell encoded commands
    ' -e(?s).*aWV4I',  # PowerShell encoded commands
    ' -e(?s).*IAB',  # PowerShell encoded commands
    ' -e(?s).*PAA',  # PowerShell encoded commands
    ' -e(?s).*aQBlAHgA',  # PowerShell encoded commands
    'vssadmin delete shadows',  # Ransomware
    'reg SAVE HKLM\\SAM',  # save registry SAM - syskey extraction
    ' -ma ',  # ProcDump
    'Microsoft\\Windows\\CurrentVersion\\Run',  # Run key in command line - often in combination with REG ADD
    '.downloadstring\(',  # PowerShell download command
    '.downloadfile\(',  # PowerShell download command
    ' /ticket:',  # Rubeus
    ' sekurlsa',  # Mimikatz
    ' p::d',  # Mimikatz 
    ';iex\(',  # PowerShell IEX
    'schtasks(?s).*/create(?s).*AppData',  # Scheduled task creation pointing to AppData
    ' comsvcs.dll,MiniDump',  # Process dumping method apart from procdump
    ' comsvcs.dll,#24'  # Process dumping method apart from procdump
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
    'cd /d '  # https://www.computerhope.com/cdhlp.htm
)

# Whoami executed as system. Array is not needed for this.

# Sysmon process create event id 1
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Sysmon/Operational'; Id='1'} | Foreach-Object {
    $entry = [xml]$_.ToXml()
    $provider = $entry.Event.System.Provider.Name
    $id = $entry.Event.System.EventID
    $time = $entry.Event.System.TimeCreated.SystemTime
    $channel = $entry.Event.System.Channel
    $computer = $entry.Event.System.Computer
    $message = $_."Message" -replace "\r\n"," " -replace "\s"," "
    $xmlcmdline = $entry.SelectSingleNode("//*[@Name='CommandLine']")."#text"
    $xmlparentcmdline = $entry.SelectSingleNode("//*[@Name='ParentCommandLine']")."#text"
    $xmlparentimage = $entry.SelectSingleNode("//*[@Name='ParentImage']")."#text"
    $xmlimage = $entry.SelectSingleNode("//*[@Name='Image']")."#text"
    $xmluser = $entry.SelectSingleNode("//*[@Name='User']")."#text"
        
        # Different suspicious or malicious command line parameters
        foreach ($c in $commandline) {
            if ($xmlcmdline -match ($c) -or $xmlparentcmdline -match ($c)) {            
                Send-Syslog "$time WinEvtLog: $channel`: EVENT-ID($id)`: $provider`: COMPUTER: $computer`: $message CollectTime: $timestamp"
            }
        }
        
        # Office Dropper Detection
        foreach ($p in $ParentImage) {
            foreach ($i in $image) {
                if($xmlparentimage -match ($p) -and $xmlimage -match ($i)) {
                    Send-Syslog "$time WinEvtLog: $channel`: EVENT-ID($id)`: $provider`: COMPUTER: $computer`: $message CollectTime: $timestamp"
                }
            }
        }

        # Webshells
        foreach ($w in $wimage) {
            foreach ($wc in $wcommandline) {
                if ($xmlimage -match ($w) -and $xmlcmdline -match ($wc)) {
                    Send-Syslog "$time WinEvtLog: $channel`: EVENT-ID($id)`: $provider`: COMPUTER: $computer`: $message CollectTime: $timestamp"
                }
            }
        }

        # Whoami as System
        if($xmluser -match 'AUTHORITY\\SYSTEM' -and $xmlimage -match '\\whoami.exe') {
            Send-Syslog "$time WinEvtLog: $channel`: EVENT-ID($id)`: $provider`: COMPUTER: $computer`: $message CollectTime: $timestamp"
        }
}

# Windows process creation event id 4688
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4688'} | Foreach-Object {
    $entry = [xml]$_.ToXml()
    $provider = $entry.Event.System.Provider.Name
    $id = $entry.Event.System.EventID
    $time = $entry.Event.System.TimeCreated.SystemTime
    $channel = $entry.Event.System.Channel
    $computer = $entry.Event.System.Computer
    $message = $_."Message" -replace "\r\n"," " -replace "\s"," "
    $xmlcmdline = $entry.SelectSingleNode("//*[@Name='CommandLine']")."#text"
    $xmlparentimage = $entry.SelectSingleNode("//*[@Name='ParentProcessName']")."#text"
    $xmlimage = $entry.SelectSingleNode("//*[@Name='NewProcessName']")."#text"
    $xmluser = $entry.SelectSingleNode("//*[@Name='SubjectUserSid']")."#text"

        # Different suspicious or malicious command line parameters
        foreach ($c in $commandline) {
            if ($xmlcmdline -match ($c)) {            
                Send-Syslog "$time WinEvtLog: $channel`: EVENT-ID($id)`: $provider`: COMPUTER: $computer`: $message CollectTime: $timestamp"
            }
        }
        
        # Office Dropper Detection
        foreach ($p in $ParentImage) {
            foreach ($i in $image) {
                if($xmlparentimage -match ($p) -and $xmlimage -match ($i)) {
                    Send-Syslog "$time WinEvtLog: $channel`: EVENT-ID($id)`: $provider`: COMPUTER: $computer`: $message CollectTime: $timestamp"
                }
            }
        }

        # Webshells
        foreach ($w in $wimage) {
            foreach ($wc in $wcommandline) {
                if ($xmlimage -match ($w) -and $xmlcmdline -match ($wc)) {
                    Send-Syslog "$time WinEvtLog: $channel`: EVENT-ID($id)`: $provider`: COMPUTER: $computer`: $message CollectTime: $timestamp"
                }
            }
        }

        # Whoami as System
        if($xmluser -eq 'S-1-5-18' -and $xmlimage -match '\\whoami.exe') {
            Send-Syslog "$time WinEvtLog: $channel`: EVENT-ID($id)`: $provider`: COMPUTER: $computer`: $message CollectTime: $timestamp"
        }
}

#  ____         ___               ____                          __              __     
# /\  _`\   __ /\_ \             /\  _`\                       /\ \__          /\ \    
# \ \ \L\_\/\_\\//\ \      __    \ \ \/\_\  _ __    __     __  \ \ ,_\    __   \_\ \   
#  \ \  _\/\/\ \ \ \ \   /'__`\   \ \ \/_/_/\`'__\/'__`\ /'__`\ \ \ \/  /'__`\ /'_` \  
#   \ \ \/  \ \ \ \_\ \_/\  __/    \ \ \L\ \ \ \//\  __//\ \L\.\_\ \ \_/\  __//\ \L\ \ 
#    \ \_\   \ \_\/\____\ \____\    \ \____/\ \_\\ \____\ \__/.\_\\ \__\ \____\ \___,_\
#     \/_/    \/_/\/____/\/____/     \/___/  \/_/ \/____/\/__/\/_/ \/__/\/____/\/__,_ /
#
#       Sysmon file create event 11

$TargetFile = @(
    '.dmp',  # dump process memory
    'Desktop\\how',  # Ransomware
    'Desktop\\decrypt',  # Ransomware
    'bloodhound.bin' # By default bloodhound drops this file to disk if not disabled by cmdline
)

Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Sysmon/Operational'; Id='11'} | Foreach-Object {
    $entry = [xml]$_.ToXml()
    $provider = $entry.Event.System.Provider.Name
    $id = $entry.Event.System.EventID
    $time = $entry.Event.System.TimeCreated.SystemTime
    $channel = $entry.Event.System.Channel
    $computer = $entry.Event.System.Computer
    $message = $_."Message" -replace "\r\n"," " -replace "\s"," "
    $xmltarfilename = $entry.SelectSingleNode("//*[@Name='TargetFilename']")."#text"

        # Targetfile
        foreach ($t in $TargetFile) {
            if ($xmltarfilename -match ($t)) {
                Send-Syslog "$time WinEvtLog: $channel`: EVENT-ID($id)`: $provider`: COMPUTER: $computer`: $message CollectTime: $timestamp"
            }
        }
}

#  ____                                __                       ____                           __      
# /\  _`\                  __         /\ \__                   /\  _`\                        /\ \__   
# \ \ \L\ \     __     __ /\_\    ____\ \ ,_\  _ __   __  __   \ \ \L\_\  __  __     __    ___\ \ ,_\  
#  \ \ ,  /   /'__`\ /'_ `\/\ \  /',__\\ \ \/ /\`'__\/\ \/\ \   \ \  _\L /\ \/\ \  /'__`\/' _ `\ \ \/  
#   \ \ \\ \ /\  __//\ \L\ \ \ \/\__, `\\ \ \_\ \ \/ \ \ \_\ \   \ \ \L\ \ \ \_/ |/\  __//\ \/\ \ \ \_ 
#    \ \_\ \_\ \____\ \____ \ \_\/\____/ \ \__\\ \_\  \/`____ \   \ \____/\ \___/ \ \____\ \_\ \_\ \__\
#     \/_/\/ /\/____/\/___L\ \/_/\/___/   \/__/ \/_/   `/___/> \   \/___/  \/__/   \/____/\/_/\/_/\/__/
#                      /\____/                            /\___/                                       
#                      \_/__/                             \/__/                                        
#
#        Sysmon registry events 12 and 13

$TargetObject = @(
    'UserInitMprLogonScript',  # persistence
    '\\CurrentVersion\\Image File Execution Options\\',  # persistence
    '\\Microsoft\\Windows\\CurrentVersion\\Run\\',  # persistence
    '\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\'   # persistence
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
    $entry = [xml]$_.ToXml()
    $provider = $entry.Event.System.Provider.Name
    $id = $entry.Event.System.EventID
    $time = $entry.Event.System.TimeCreated.SystemTime
    $channel = $entry.Event.System.Channel
    $computer = $entry.Event.System.Computer
    $message = $_."Message" -replace "\r\n"," " -replace "\s"," "
    $xmltarobject = $entry.SelectSingleNode("//*[@Name='TargetObject']")."#text"
    $xmldetails = $entry.SelectSingleNode("//*[@Name='Details']")."#text"

        # TargetObject
        foreach ($to in $targetobject) {
            if ($xmltarobject -match ($to)) {
                Send-Syslog "$time WinEvtLog: $channel`: EVENT-ID($id)`: $provider`: COMPUTER: $computer`: $message CollectTime: $timestamp"
            }
        }

        # Details
        foreach ($d in $details) {
            if ($xmldetails -match ($d)) {
                Send-Syslog "$time WinEvtLog: $channel`: EVENT-ID($id)`: $provider`: COMPUTER: $computer`: $message CollectTime: $timestamp"
            }
        }
}

#    _____            __                    _______    __           __      
#   / ___/__  _______/ /____  ____ ___     / ____/ |  / /__  ____  / /______
#   \__ \/ / / / ___/ __/ _ \/ __ `__ \   / __/  | | / / _ \/ __ \/ __/ ___/
#  ___/ / /_/ (__  ) /_/  __/ / / / / /  / /___  | |/ /  __/ / / / /_(__  ) 
# /____/\__, /____/\__/\___/_/ /_/ /_/  /_____/  |___/\___/_/ /_/\__/____/  
#      /____/                                                               
#        
#        Malicious service installs

$ServiceName = @(
    'WCESERVICE',
    'WCE SERVICE',
    'winexesvc',
    'DumpSvc',
    'pwdump',
    'gsecdump',
    'cachedump'
)

$ServiceFilename = @(
    '\\\\.\\pipe', # Possible get-system usage. Named pipe service - https://blog.cobaltstrike.com/2014/04/02/what-happens-when-i-type-getsystem/
    '\\\\127.0.0.1\\' # Detects smbexec from Impacket framework - https://neil-fox.github.io/Impacket-usage-&-detection/
)

Get-WinEvent -FilterHashtable @{ LogName='System'; Id='7045'} | Foreach-Object {
    $entry = [xml]$_.ToXml()
    $provider = $entry.Event.System.Provider.Name
    $id = $entry.Event.System.EventID.Qualifiers
    $time = $entry.Event.System.TimeCreated.SystemTime
    $channel = $entry.Event.System.Channel
    $computer = $entry.Event.System.Computer
    $message = $_."Message" -replace "\r\n"," " -replace "\s"," "
    $xmlservicename = $entry.SelectSingleNode("//*[@Name='ServiceName']")."#text"
    $xmlserviceFilename = $entry.SelectSingleNode("//*[@Name='ImagePath']")."#text"

        foreach ($s in $ServiceName) {
            if ($xmlservicename -match ($s)) {
                Send-Syslog "$time WinEvtLog: $channel`: EVENT-ID($id)`: $provider`: COMPUTER: $computer`: $message CollectTime: $timestamp"
            }
        }

        foreach ($sf in $ServiceFilename) {
            if ($xmlservicefilename -match ($sf)) {
                Send-Syslog "$time WinEvtLog: $channel`: EVENT-ID($id)`: $provider`: COMPUTER: $computer`: $message CollectTime: $timestamp"
            }
        }
}

#  __          __ _             _         __                  _ 
#  \ \        / /(_)           | |       / _|                | |
#   \ \  /\  / /  _  _ __    __| |  ___ | |_  ___  _ __    __| |
#    \ \/  \/ /  | || '_ \  / _` | / _ \|  _|/ _ \| '_ \  / _` |
#     \  /\  /   | || | | || (_| ||  __/| | |  __/| | | || (_| |
#      \/  \/    |_||_| |_| \__,_| \___||_|  \___||_| |_| \__,_|
#
# Windows Defender event id 1116 and 1117
# 1116 Windows Defender Antivirus has detected malware or other potentially unwanted software
# 1117 Windows Defender Antivirus has taken action to protect this machine from malware or other potentially unwanted software.

Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Windows Defender/Operational'; Id=1116,1117} | Foreach-Object {
    $entry = [xml]$_.ToXml()
    $provider = $entry.Event.System.Provider.Name
    $id = $entry.Event.System.EventID.Qualifiers
    $time = $entry.Event.System.TimeCreated.SystemTime
    $channel = $entry.Event.System.Channel
    $computer = $entry.Event.System.Computer
    $message = $_."Message" -replace "\r\n"," " -replace "\s"," "
    $xmlservicename = $entry.SelectSingleNode("//*[@Name='ServiceName']")."#text"
    
    Send-Syslog "$time WinEvtLog: $channel`: EVENT-ID($id)`: $provider`: COMPUTER: $computer`: $message CollectTime: $timestamp"
}
