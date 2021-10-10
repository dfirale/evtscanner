## INTRO

Powershell script to scan Windows eventlog with Sigma rules and send the results to syslog endpoint. This doesn't include all Sigma rules but the ones that are most effective.

All conditions included from Florian Roth's Godmode Sigma rule: https://github.com/Neo23x0/sigma/blob/master/other/godmode_sigma_rule.yml

Some additional rules also included which I found relevant.

More detailed explanation in this blog post: https://dfirale.github.io/dfir/2021/03/01/Finding-evil-with-Powershell-and-Get-WinEvent.html

![stats](https://user-images.githubusercontent.com/24719957/136694077-36518a0a-d26b-47fb-a1ad-c41233ccd0f6.png)

## REQUIREMENTS

- (Recommended) Sysmon installed

- (Optional) Commandline auditing on Windows process create events

## USAGE

1.) Powershell needs to be run with elevated privileges (admin/system). Deploy the script through GPO or run with PsExec etc. 

2.) Pass the syslog endpoint ip as parameter - example: 
```
.\evtscanner.ps1 -ip 192.168.1.1
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

## Updates

### 2021-10-10 
- Commandline indicators on process create events
- Sysmon Pipe event (17) indicators (malware, Cobalt Strike, PWdumpers, RCE)
- Couple system event (7045) indicators
- Shorten and beautify code

## TODO

- Add more rules
- Function to scan .evtx files exported from another host
- Function to generate html or csv results locally 
- Process the receiver results to html or csv
