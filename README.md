# Ransomware_PoC
A simple ransomware for testing

# Build
gcc ransomware_win32.cpp -o ransomware_win32

# Usages 
```
tool.exe <mode> <folder>
  arg1 - mode
    0: Decryption
    1: Encryption
  arg2 - file I/O sequence
    0: Write the new file and delete the original file
    1: Overwrite the original file and rename
    2: Move the new file to the original file
    3: RIPlace - move the new file to the original file by DefineDosDeviceA
    4: Overwrite the original files by fileamapping
  arg3 - target folder
  arg4 - wallpaper source location
  arg5 - ransom note location
```
