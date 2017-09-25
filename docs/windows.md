# Windows support

To update descriptions run (assumes `cl` cross-compiler is in PATH):
```
syz-extract -os=windows
syz-sysgen
```

To build binaries:
```
go build -o bin/windows_amd64/syz-stress.exe ./tools/syz-stress
cl executor\executor_windows.cc /EHsc -o bin\windows_amd64\syz-executor.exe
```

To run:
```
bin\windows_amd64\syz-stress.exe -executor c:\full\path\to\bin\windows_amd64\syz-executor.exe -cover=0
```
