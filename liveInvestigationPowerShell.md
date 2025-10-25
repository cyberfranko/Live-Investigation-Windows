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

#### Identifying Suspicious Network Activity
- Abnormal for the associated process
    - Notepad making connections to port 80
    - Service making multiple outbound connections (Could be an updater)
- Abnormal for the environment
    - Lots of activity during off hours
    - Long running HTTP/HTPPS sessions
    - Beaconing
- Technique specific
    - Lateral movement implies connections to other internal hosts
- Known malicious hosts/addresses
    - Based on threat intelligence
    - From the incident or other process/connections (i.e. pivoting)

##### Examining Services
```powershell
Get-Service
```

```
Get-CimInstance -ClassName Win32_Service | Format-List Name,Caption,Description,PathName
```

#### Registry Interrogation
- 'Get-ChildItem': Like navigating a file system, we can examine the registry keys using with HKLM: or HKCU: prefix
- 'Get-ItemProperty': For a given registry key, examine the values
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\' | Select-Object PSChildName

Get-ItemProperty 'HKLM:Software\Microsoft\Windows\CurrentVersion\Run'
```

To navigate registry keys, we can use Get-ChildItem with a registry key path to list key contents (or use the PowerShell alias dir) or change to the registry location using Set-Location (or the alias cd) and use Get-Child-Item from the working registry key location.

#### Unusual Accounts

Look for new, unexpected accounts in the adnimistrators group
```powershell
Get-LocalUser

Get-LocalUser | Where-Object ( 0_.Enabled -eq $True )
Get-LocalGroup

Get-LocalGroupMember Administrators
```

#### Unusual Scheduled Tasks
- Look for unusual scheduled tasks: Get-ScheduledTask
- Export scheduled task for command details: Export-ScheduledTask
- Examine last run status: Get-ScheduledTaskInfo

```powhershell
Get-ScheduledTask *Avast* | Select-Object -Property TaskName

Export-ScheduledTask -TaskName 'AvastUpdate'

Get-ScheduledTaskInfo -TaskName 'AvastUpdatre' | Select-Object LastRunTime
```

##### Unusual Log Entries
```powershell
$start = Get-Date 3/1/2022;
$end = Get-Date 3/31/2022;
Get-WinEvent -FilterHashTable @{LogName='Security'; StartTime=$start; EndTime=$end;}

Get-WinEvent -LogName System | Where-Object -Property Id -EQ 7045 | Format-List -Property TimeCreated,Message

Get-WinEvent -ListLog | Select LogName,RecordCount
```

#### Differential Analysis
```powershell
Get-Service > baseline-services-20220325.txt

Get-Service > services-liveinvestigation.txt

$baseline = Get-Content .\baseline-services-20220325.txt

$current = Get-Content .\services-liveinvestigation.txt

Compare-Object -ReferenceObject $baseline -DifferenceObject $current
```

 

