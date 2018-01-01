# CMDCHECK

This volatility plugin scans memory for `cmd.exe` execution and checks the standard handles.

If cmd.exe is being used for data exfiltration (or other unwanted activity) it is likely that the handles will change. This is a good way to check for backdoors / modification (Pages 230 - 232 of The Art of Memory Forensics).

## Use

1. Download the plugin to a local filesystem
2. Run the plugin against a memory image: `python vol.py --plugins={path/to/plugin} --profile={image profile} -f {memory.img} cmdcheck`
3. Any deviation from the norm will be annotated with **!*!**
4. Note: *This does not work if the process has exited memory*

## IR Notes

* Modified handles in cmd.exe is an indicator of malice.
