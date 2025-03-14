# Source Tickrate (Server addon)

A _standalone_ **Source Engine** server addon that enables the `-tickrate` command line parameter.

Currently tested on:
* Counter-Strike: Source (32-bit & 64-bit)
* Team Fortress 2 (32-bit & 64-bit)

**Note**: This plugin may also work on other source games, but it's untested. If there's a Source game you'd like it to work on, and you've confirmed it doesn't work, then please feel free to open an issue or pull request.

## Usage & Installation

Download a release zip from [here](https://github.com/angelfor3v3r/source-tickrate/releases) and extract the `addons` folder into your server's game mod folder (i.e. `cstrike`, `tf`, etc).

You can now pass `-tickrate <Desired Tickrate>` on the command line.
Example for **Counter-Strike: Source**:
```
srcds.exe -console -game cstrike +maxplayers 10 +map de_nuke -tickrate 100
```

Note that you must set ConVars such as `sv_maxupdaterate`, `sv_maxcmdrate`, etc. to accommodate the new tickrate setting.

## Building

If the releases don't fit your needs then you can build the library yourself.\
Building requires **CMake 3.15** (or later) and a **C++17** ready compiler.

Here are some examples (assuming a 64-bit OS):

### Windows (MSVC):

```
64-bit:
    cmake -G "Visual Studio 17 2022" -A x64 -B cmake-build-x86_64
    cmake --build cmake-build-x86_64 --config Release
    
32-bit:
    cmake -G "Visual Studio 17 2022" -A Win32 -B cmake-build-x86_32
    cmake --build cmake-build-x86_32 --config Release
```

### Linux (GCC):

```
64-bit: 
    cmake -B cmake-build-x86_64 -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++ -DCMAKE_BUILD_TYPE=Release
    cmake --build cmake-build-x86_64 --config Release
    
32-bit: 
    cmake -B cmake-build-x86_32 -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++ -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_FLAGS=-m32 -DCMAKE_C_FLAGS=-m32 -DCMAKE_BUILD_TYPE=Release
    cmake --build cmake-build-x86_32 --config Release
```

## Thanks
[SafetyHook](https://github.com/cursey/safetyhook)\
[Zydis](https://github.com/zyantific/zydis)\
[expected](https://github.com/TartanLlama/expected)\
[{fmt}](https://github.com/fmtlib/fmt)\
[CPM.cmake](https://github.com/cpm-cmake/CPM.cmake)
