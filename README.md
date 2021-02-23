## INTRO

Powershell script to scan Windows eventlog with Sigma rules and send the results to syslog endpoint. This doesn't include all Sigma rules but the ones that are most effective.

All conditions included from Florian Roth's Godmode Sigma rule: https://github.com/Neo23x0/sigma/blob/master/other/godmode_sigma_rule.yml

Some additional rules also included which I found important. Might add some more later!

## REQUIREMENTS

- (Recommended) Sysmon installed
- (Optional) Commandline auditing on Windows process create events

## USAGE

1.) Powershell needs to be run with elevated privileges (admin/system). Deploy the script through GPO or run with PsExec etc. 

2.) Pass the syslog endpoint ip as parameter - example: 
```
.\evtxscanner.ps1 -ip 192.168.1.1
```

3.) OPTIONAL - If you don't have a syslog endpoint/receiver you can use these really simple receivers provided in this repo

Powershell: Specify parameters port and file
```
.\syslogreceiver.ps1 -port 514 -file C:\Users\Johndoe\Desktop\events.txt
```
Python: Predefined port is 514 (default port for syslog). Edit the script if you wish to change the logfile. Default is events.log in the current directory. 
```
python3 syslogreceiver.py
```
