# Ghidra ReAGS plugin

A plugin for Ghidra SRE framework to import and analyze Adventure Game Studio (AGS) compiled scripts (scom3).

It allows you to decompile and reverse-engineer AGS scripts.

## Current status

> [!WARNING]
> At this moment project is in halfway finished state and currently no longer being developed.

Although it can be used even in this state don't expect a smooth experience.

### Supported versions

* Ghidra 10.4

## Known issues

* **MAJOR**: Analysis state is not being saved into project files (that means you'll **\_\_LOSE\_\_** all your work when CodeBrowser window is closed).
* Sometimes decompilation is incorrect (you'll now it when you see it).
* P-code emulation won't work correctly.
* No data archives provided (there's AGS341.gdt, but it's just a test thing).

## License

**Ghidra** itself is licensed under **Apache License 2.0** (see Apache_License_2_0.txt).

**ReAGS** plugin is licensed under **Public Domain** (see LICENSE).

Files "filearchives/agsdefns.sh" and "filearchives/agsdefns_original_321.sh" are taken from AGS project source (https://github.com/adventuregamestudio/ags) with no modifications.
