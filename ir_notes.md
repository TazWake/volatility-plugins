# This document will hold tips and guidance for memory related IR

## Keyloggers
Looking for classic windows functions used by keyloggers - use strings & grep on dumped process files (such as Malfind output)


```strings {object} | grep -i -E "GetAsyncnKeyState|SetWindowsHookEx|WH_KEYBOARD|WH_KEYBOARD_LL|GetKeyboardStat"```

## To-Do List
- capturing memory
- proc hollowing / injection
- more from art of memory forensics
- file-less malware
