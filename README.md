# Simple-DLL-Injection-Rust

Down to its core they all just call LoadLibraryW,
but there are different methods of calling it:

```
- LoadLibrary
- ThreadHijacking
- NtCreateThreadEx [x86_64 ONLY]; because I keep getting status violation HAHAA *help*
```

To use this, build to correct architecture (and ofc use the correct DLLs),
e.g.
for 32 bit:

```
cargo build --target=i686-pc-windows-msvc --release
```

for 64 bit:

```
cargo build --target=x86_64-pc-windows-msvc --release
```

Created for educational purposes.
Sources Used:

https://stackoverflow.com/questions/865152/how-can-i-get-a-process-handle-by-its-name-in-c
https://en.wikipedia.org/wiki/DLL_injection
https://www.youtube.com/watch?v=PEMkcbY8U9o
https://github.com/Aluma010/DLL-Injection
https://shellblade.net/hacking/code-cave-windows.html
https://github.com/guided-hacking/GuidedHacking-Injector/tree/master/GH%20Injector%20Library/GH%20Injector%20Library

Thanks to all sources and creators
I have gained more brain cells than I have had
before!
