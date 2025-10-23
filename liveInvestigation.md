---
Title: PowerShell Live Investigation PowerShell Commands
---

- Powerful command interpreter and scripting language
- Primarily Windows, but also available for UNIX
- Powerful pipelining capabilities, data access, and filtering options.

#### Examining Processes
Get brief information about running processes
```powershell
Get-Process
```
Get brief information about a named process with wildcard
```powershell
Get-Process 'powersh*'
```
Detailed information
```powershell
Get-Process 'powershell' | Select-Object *
```
Remote Systems
```powershell
Get-Process -ComputerName SEC504STUDENT
```

A foundational activity for examining a live sytem is to investigate running processes. Cmdlets are PowerShell commands that perform some functionality, often retrieving data.
'Get-Process' also accepts arguments, including a specific process name. We can also use one or more asterisk wildcards to match multiple processes.

When you invoke 'Get-Process' it returns an object.

#### Get-CimInstance Process Data
```powershell
Get-CimInstance -Class Win32_Process | Select-Object ProcessId,ProcessName,CommandLine
```
'Get-Process' doesn't capture some useful process details
```powershell
 Get-Process 'lsass' | Select-Object -Property Id
```
531
```
Get-CimInstance -Class -Class Win32_Process | Where-Object -Property ParentProcessId -EQ 531
```

#### Identifying Suspicious Processes
- Is it a new or unrecognized process?
- Is the name random looking?
- Is it running from a non-standard path?
- Is the parent suspicious?
- Is the parent-child relationship suspicious?
- Is it tied to suspicious activity?
- Base64 encoded command-line options?

Cyberchef is useful for encoding and decoding any data, not just process-related information. 
It is common to see different types of data encoding in attacker tools and in many other areas that you will be called upon to investigate as an analyst.

#### Examining Network Usage
```powershell
Get-NetTCPConnection

Get-NetTCPConnection -State Listen | Select-Object -Property,LocalAddress,LocalPort,OwningProcess

Get-NetTCPConnection -RemoteAddress 10.10.75.1 | Select-Object,CreationTime,LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess,State
```

One challenge with Get-NetTCPConnection is that, while it can reveal the process ID associated with the network connection, it does not show you the process name. Once you get the process ID, however, you can look up the process name using Get-Process -Id processid. Or this PowerShell command will retrieve both the network connection details and the process name in one command, using a hash table with the @ {} syntax.
```powershell
Get-NetTCPConnection | Select-Object local*,remote*,state,@{Name='Process';Expression={(Get-Process -Id $_.OwningProcess).ProcessName}} | Format-Table
```

























