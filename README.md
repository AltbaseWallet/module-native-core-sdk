# Altbase Native Core

This process is the native C++ boundary for wallet-sensitive logic.

The Electron app talks to it over newline-delimited JSON on stdin/stdout:

```json
{"id":"1","method":"health","params":{}}
```

Responses are also one JSON object per line:

```json
{"id":"1","ok":true,"result":{"service":"altbase-core"}}
```

Build from a Visual Studio Developer PowerShell:

```powershell
cmake --preset vs2022-x64-release
cmake --build --preset vs2022-x64-release
```

The first milestone keeps the UI unchanged and moves the command boundary into
C++. The remaining JS wallet code can then be replaced command by command.
