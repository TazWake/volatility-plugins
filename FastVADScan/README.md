# Fast VAD Scan

This is a volatility plugin, similar to malfind, which looks at the number of pages committed and the VAD settings. It **does not** extract files so may run faster.

When executed this plugin will return the process name and PID for any process which has more than 30 pages committed and RWX set.

## How to use Fast VAD Scan

1. Download the plugin to a local filesystem location
2. Run volatility calling the plugin: `python vol.py --plugins={path/to/plugins} --profile={image profile} -f {filename} fastvadscan`
3. Review output and determine if any files warrant further investigation

## IR Notes

* This is a triage tool and works best if you have suspicious files
* It can narrow down files for further analysis
* If file extraction is required, run malfind
