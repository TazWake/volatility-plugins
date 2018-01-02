# Path Check
This plugin scans the capture and identifies an executables which appear to have been loaded from a temp, download or user location. The choice of locations is arbritrary and can be adjusted to suit the investigation.
The location matching is case insensitive so will match `temp`, `Temp` and `TEMP` in a path.

## How to use Path Check
1. Download the plugin to a local files store
2. Invoke volatility (with the plugins folder before anything else) calling pathcheck. For example: `python vol.py --plugins={path/to/plugins} --profile={profile for memory image} -f {path to image} pathcheck`
3. Review the output - processes executed from temp / download or user locations are more likely to be malware and should be subject to further investigation.

## IR Use
This tool is best used as part of the triage process to get a quick feel for what suspicious activity is on the system.

Alternatively, it can be used as part of a threat hunting review via a remote access agent (such as F-Response)
