# Triagecheck

This volatility plugin is designed to quickly parse the process list and identify some **obvious** signs of malicious activity. It is not designed to act as an indepth assessment tool and works best for investigators looking to triage multiple platforms quickly. 

The plugin highlights the following events:
+ CSRSS - there should only be one instance and it should run from the system32 folder
+ SVCHOST - check for impersonation (e.g. scvhost / svch0st etc)
