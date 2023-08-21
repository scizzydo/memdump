# memdump

memdump is a tool for taking a Windows x64 PE file and launching it, and writing back to disk. The purpose being some files on disk differ from the final result when loaded in memory.

The idea behind this tool is based off of namreeb's dumpwow. Although that tool already exists, it had a few problems with it (I appologize for not just doing a PR to it, but wanted to learn more also).

Key features that differ:
- No third party libraries needed in any bit, outside just normal Windows libraries
- Fast dumping to disk
- No need for DLL and exe. Just 1 file to handle it all
- Addresses issues to TLS callbacks when loading binary into IDA
- Addresses issues with binary analysis not seeing all data due to headers not being fully updated
- Addresses issues with binaires that require SizeOfHeaders to be updated as the new section will extend past the original
- Provides minor tweaks that weren't provided from hadesmem pelib section

Credits: 
- hadesmem memory library https://github.com/namreeb/hadesmem
- dumpwow https://github.com/namreeb/dumpwow
- nmd length disassembler https://github.com/Nomade040/nmd