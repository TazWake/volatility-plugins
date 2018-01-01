# Volatility-Learning
I am in the process of learning how to create volatility plugins. This repo will be used as a storage platform for them.

In the event that anything of actual value is created (rather than just a rework of existing ones as I try to understand the commands) it will be migrated to a new location.

## RAMSCAN
The first volatility plugin is `ramscan.py`. 
This plugin lists running processes with PID and Parent PID, Command Line used to invoke the process and a check to see what the VAD settings are. If the VAD is set to Read, Write, Execute it is marked as suspicious.

### How to use ramscan.py
1. Download the plugin to a folder on your local machine.
2. Invoke volatility calling the plugins folder before anything else. eg: `python vol.py --plugins={path/to/plugins} --profile={profile for memory image} -f {path to image} ramscan`
3. A more useable method is to set an output format and output file as the data presented by this plugin can quickly fill a console window.

*recommended use*

`python vol.py --plugins={path/to/plugins} --profile={profile for memory image} -f {path to image} ramscan --output=html --output-file=ramscan.html`

### Example output

```
Name           PID  Parent Command Line   VAD               
System            4      0                                   
smss.exe        504      4 \SystemRoot\temp\smss.exe
conhost.exe    6248    748 \??\C:\WINDOWS\system32\conhost.exe "9131723291973856416-156581232056986786412445124951738786652-244451647283318875 Suspicious RWX VAD
scPopup.exe    6284   4616 "C:\Program Files\Xerox\scPopup.exe" /s /k /t /g Suspicious RWX VAD
GROOVE.EXE     6384   4616 "C:\Program Files\Microsoft Office 15\root\office15\GROOVE.EXE" /RunFolderSync /TrayOnly  Suspicious RWX VAD
mobsync.exe    6672    936 C:\WINDOWS\System32\mobsync.exe -Embedding Suspicious RWX VAD
ucmapi.exe     5748    936 "C:\Program Files\Microsoft Office 15\Root\Office15\UcMapi.exe" -Embedding Suspicious RWX VAD
powershell.exe 5772   6188 powershell -nop -exec bypass -EncodedCommand SQBFAFgAIAAoACgAbgBlAHcALQBvAGIA...ACcAaAB0AHQAcAA6AC8ALwAxADIANwAuADAALgAwAC4AMQA6ADUAMgA4ADAAOAAvACcAKQApAA== Suspicious RWX VAD
```
### IR Use
* Look for command execution from unusual locations
* Look for suspicious command execution: Eg encoded Powershell
* Look for memory sections which allow read-write-execute
