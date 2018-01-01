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
