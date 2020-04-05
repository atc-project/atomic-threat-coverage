| Title                    | Malicious PowerShell Commandlets       |
|:-------------------------|:------------------|
| **Description**          | Detects Commandlet names from well-known PowerShell exploitation frameworks |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Penetration testing</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://adsecurity.org/?p=2921](https://adsecurity.org/?p=2921)</li></ul>  |
| **Author**               | Sean Metcalf (source), Florian Roth (rule) |


## Detection Rules

### Sigma rule

```
title: Malicious PowerShell Commandlets
id: 89819aa4-bbd6-46bc-88ec-c7f7fe30efa6
status: experimental
description: Detects Commandlet names from well-known PowerShell exploitation frameworks
modified: 2019/01/22
references:
    - https://adsecurity.org/?p=2921
tags:
    - attack.execution
    - attack.t1086
author: Sean Metcalf (source), Florian Roth (rule)
date: 2017/03/05
logsource:
    product: windows
    service: powershell
    definition: 'It is recommended to use the new "Script Block Logging" of PowerShell v5 https://adsecurity.org/?p=2277'
detection:
    keywords:
        Message:
            - "*Invoke-DllInjection*"
            - "*Invoke-Shellcode*"
            - "*Invoke-WmiCommand*"
            - "*Get-GPPPassword*"
            - "*Get-Keystrokes*"
            - "*Get-TimedScreenshot*"
            - "*Get-VaultCredential*"
            - "*Invoke-CredentialInjection*"
            - "*Invoke-Mimikatz*"
            - "*Invoke-NinjaCopy*"
            - "*Invoke-TokenManipulation*"
            - "*Out-Minidump*"
            - "*VolumeShadowCopyTools*"
            - "*Invoke-ReflectivePEInjection*"
            - "*Invoke-UserHunter*"
            - "*Find-GPOLocation*"
            - "*Invoke-ACLScanner*"
            - "*Invoke-DowngradeAccount*"
            - "*Get-ServiceUnquoted*"
            - "*Get-ServiceFilePermission*"
            - "*Get-ServicePermission*"
            - "*Invoke-ServiceAbuse*"
            - "*Install-ServiceBinary*"
            - "*Get-RegAutoLogon*"
            - "*Get-VulnAutoRun*"
            - "*Get-VulnSchTask*"
            - "*Get-UnattendedInstallFile*"
            - "*Get-ApplicationHost*"
            - "*Get-RegAlwaysInstallElevated*"
            - "*Get-Unconstrained*"
            - "*Add-RegBackdoor*"
            - "*Add-ScrnSaveBackdoor*"
            - "*Gupt-Backdoor*"
            - "*Invoke-ADSBackdoor*"
            - "*Enabled-DuplicateToken*"
            - "*Invoke-PsUaCme*"
            - "*Remove-Update*"
            - "*Check-VM*"
            - "*Get-LSASecret*"
            - "*Get-PassHashes*"
            - "*Show-TargetScreen*"
            - "*Port-Scan*"
            - "*Invoke-PoshRatHttp*"
            - "*Invoke-PowerShellTCP*"
            - "*Invoke-PowerShellWMI*"
            - "*Add-Exfiltration*"
            - "*Add-Persistence*"
            - "*Do-Exfiltration*"
            - "*Start-CaptureServer*"
            - "*Get-ChromeDump*"
            - "*Get-ClipboardContents*"
            - "*Get-FoxDump*"
            - "*Get-IndexedItem*"
            - "*Get-Screenshot*"
            - "*Invoke-Inveigh*"
            - "*Invoke-NetRipper*"
            - "*Invoke-EgressCheck*"
            - "*Invoke-PostExfil*"
            - "*Invoke-PSInject*"
            - "*Invoke-RunAs*"
            - "*MailRaider*"
            - "*New-HoneyHash*"
            - "*Set-MacAttribute*"
            - "*Invoke-DCSync*"
            - "*Invoke-PowerDump*"
            - "*Exploit-Jboss*"
            - "*Invoke-ThunderStruck*"
            - "*Invoke-VoiceTroll*"
            - "*Set-Wallpaper*"
            - "*Invoke-InveighRelay*"
            - "*Invoke-PsExec*"
            - "*Invoke-SSHCommand*"
            - "*Get-SecurityPackages*"
            - "*Install-SSP*"
            - "*Invoke-BackdoorLNK*"
            - "*PowerBreach*"
            - "*Get-SiteListPassword*"
            - "*Get-System*"
            - "*Invoke-BypassUAC*"
            - "*Invoke-Tater*"
            - "*Invoke-WScriptBypassUAC*"
            - "*PowerUp*"
            - "*PowerView*"
            - "*Get-RickAstley*"
            - "*Find-Fruit*"
            - "*HTTP-Login*"
            - "*Find-TrustedDocuments*"
            - "*Invoke-Paranoia*"
            - "*Invoke-WinEnum*"
            - "*Invoke-ARPScan*"
            - "*Invoke-PortScan*"
            - "*Invoke-ReverseDNSLookup*"
            - "*Invoke-SMBScanner*"
            - "*Invoke-Mimikittenz*"
            - "*Invoke-AllChecks*"
    false_positives:
        - Get-SystemDriveInfo  # http://bheltborg.dk/Windows/WinSxS/amd64_microsoft-windows-maintenancediagnostic_31bf3856ad364e35_10.0.10240.16384_none_91ef7543a4514b5e/CL_Utility.ps1
    condition: keywords and not false_positives
falsepositives:
    - Penetration testing
level: high

```





### es-qs
    
```
(Message.keyword:(*Invoke\\-DllInjection* OR *Invoke\\-Shellcode* OR *Invoke\\-WmiCommand* OR *Get\\-GPPPassword* OR *Get\\-Keystrokes* OR *Get\\-TimedScreenshot* OR *Get\\-VaultCredential* OR *Invoke\\-CredentialInjection* OR *Invoke\\-Mimikatz* OR *Invoke\\-NinjaCopy* OR *Invoke\\-TokenManipulation* OR *Out\\-Minidump* OR *VolumeShadowCopyTools* OR *Invoke\\-ReflectivePEInjection* OR *Invoke\\-UserHunter* OR *Find\\-GPOLocation* OR *Invoke\\-ACLScanner* OR *Invoke\\-DowngradeAccount* OR *Get\\-ServiceUnquoted* OR *Get\\-ServiceFilePermission* OR *Get\\-ServicePermission* OR *Invoke\\-ServiceAbuse* OR *Install\\-ServiceBinary* OR *Get\\-RegAutoLogon* OR *Get\\-VulnAutoRun* OR *Get\\-VulnSchTask* OR *Get\\-UnattendedInstallFile* OR *Get\\-ApplicationHost* OR *Get\\-RegAlwaysInstallElevated* OR *Get\\-Unconstrained* OR *Add\\-RegBackdoor* OR *Add\\-ScrnSaveBackdoor* OR *Gupt\\-Backdoor* OR *Invoke\\-ADSBackdoor* OR *Enabled\\-DuplicateToken* OR *Invoke\\-PsUaCme* OR *Remove\\-Update* OR *Check\\-VM* OR *Get\\-LSASecret* OR *Get\\-PassHashes* OR *Show\\-TargetScreen* OR *Port\\-Scan* OR *Invoke\\-PoshRatHttp* OR *Invoke\\-PowerShellTCP* OR *Invoke\\-PowerShellWMI* OR *Add\\-Exfiltration* OR *Add\\-Persistence* OR *Do\\-Exfiltration* OR *Start\\-CaptureServer* OR *Get\\-ChromeDump* OR *Get\\-ClipboardContents* OR *Get\\-FoxDump* OR *Get\\-IndexedItem* OR *Get\\-Screenshot* OR *Invoke\\-Inveigh* OR *Invoke\\-NetRipper* OR *Invoke\\-EgressCheck* OR *Invoke\\-PostExfil* OR *Invoke\\-PSInject* OR *Invoke\\-RunAs* OR *MailRaider* OR *New\\-HoneyHash* OR *Set\\-MacAttribute* OR *Invoke\\-DCSync* OR *Invoke\\-PowerDump* OR *Exploit\\-Jboss* OR *Invoke\\-ThunderStruck* OR *Invoke\\-VoiceTroll* OR *Set\\-Wallpaper* OR *Invoke\\-InveighRelay* OR *Invoke\\-PsExec* OR *Invoke\\-SSHCommand* OR *Get\\-SecurityPackages* OR *Install\\-SSP* OR *Invoke\\-BackdoorLNK* OR *PowerBreach* OR *Get\\-SiteListPassword* OR *Get\\-System* OR *Invoke\\-BypassUAC* OR *Invoke\\-Tater* OR *Invoke\\-WScriptBypassUAC* OR *PowerUp* OR *PowerView* OR *Get\\-RickAstley* OR *Find\\-Fruit* OR *HTTP\\-Login* OR *Find\\-TrustedDocuments* OR *Invoke\\-Paranoia* OR *Invoke\\-WinEnum* OR *Invoke\\-ARPScan* OR *Invoke\\-PortScan* OR *Invoke\\-ReverseDNSLookup* OR *Invoke\\-SMBScanner* OR *Invoke\\-Mimikittenz* OR *Invoke\\-AllChecks*) AND (NOT \\*.keyword:(*Get\\-SystemDriveInfo*)))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/89819aa4-bbd6-46bc-88ec-c7f7fe30efa6 <<EOF\n{\n  "metadata": {\n    "title": "Malicious PowerShell Commandlets",\n    "description": "Detects Commandlet names from well-known PowerShell exploitation frameworks",\n    "tags": [\n      "attack.execution",\n      "attack.t1086"\n    ],\n    "query": "(Message.keyword:(*Invoke\\\\-DllInjection* OR *Invoke\\\\-Shellcode* OR *Invoke\\\\-WmiCommand* OR *Get\\\\-GPPPassword* OR *Get\\\\-Keystrokes* OR *Get\\\\-TimedScreenshot* OR *Get\\\\-VaultCredential* OR *Invoke\\\\-CredentialInjection* OR *Invoke\\\\-Mimikatz* OR *Invoke\\\\-NinjaCopy* OR *Invoke\\\\-TokenManipulation* OR *Out\\\\-Minidump* OR *VolumeShadowCopyTools* OR *Invoke\\\\-ReflectivePEInjection* OR *Invoke\\\\-UserHunter* OR *Find\\\\-GPOLocation* OR *Invoke\\\\-ACLScanner* OR *Invoke\\\\-DowngradeAccount* OR *Get\\\\-ServiceUnquoted* OR *Get\\\\-ServiceFilePermission* OR *Get\\\\-ServicePermission* OR *Invoke\\\\-ServiceAbuse* OR *Install\\\\-ServiceBinary* OR *Get\\\\-RegAutoLogon* OR *Get\\\\-VulnAutoRun* OR *Get\\\\-VulnSchTask* OR *Get\\\\-UnattendedInstallFile* OR *Get\\\\-ApplicationHost* OR *Get\\\\-RegAlwaysInstallElevated* OR *Get\\\\-Unconstrained* OR *Add\\\\-RegBackdoor* OR *Add\\\\-ScrnSaveBackdoor* OR *Gupt\\\\-Backdoor* OR *Invoke\\\\-ADSBackdoor* OR *Enabled\\\\-DuplicateToken* OR *Invoke\\\\-PsUaCme* OR *Remove\\\\-Update* OR *Check\\\\-VM* OR *Get\\\\-LSASecret* OR *Get\\\\-PassHashes* OR *Show\\\\-TargetScreen* OR *Port\\\\-Scan* OR *Invoke\\\\-PoshRatHttp* OR *Invoke\\\\-PowerShellTCP* OR *Invoke\\\\-PowerShellWMI* OR *Add\\\\-Exfiltration* OR *Add\\\\-Persistence* OR *Do\\\\-Exfiltration* OR *Start\\\\-CaptureServer* OR *Get\\\\-ChromeDump* OR *Get\\\\-ClipboardContents* OR *Get\\\\-FoxDump* OR *Get\\\\-IndexedItem* OR *Get\\\\-Screenshot* OR *Invoke\\\\-Inveigh* OR *Invoke\\\\-NetRipper* OR *Invoke\\\\-EgressCheck* OR *Invoke\\\\-PostExfil* OR *Invoke\\\\-PSInject* OR *Invoke\\\\-RunAs* OR *MailRaider* OR *New\\\\-HoneyHash* OR *Set\\\\-MacAttribute* OR *Invoke\\\\-DCSync* OR *Invoke\\\\-PowerDump* OR *Exploit\\\\-Jboss* OR *Invoke\\\\-ThunderStruck* OR *Invoke\\\\-VoiceTroll* OR *Set\\\\-Wallpaper* OR *Invoke\\\\-InveighRelay* OR *Invoke\\\\-PsExec* OR *Invoke\\\\-SSHCommand* OR *Get\\\\-SecurityPackages* OR *Install\\\\-SSP* OR *Invoke\\\\-BackdoorLNK* OR *PowerBreach* OR *Get\\\\-SiteListPassword* OR *Get\\\\-System* OR *Invoke\\\\-BypassUAC* OR *Invoke\\\\-Tater* OR *Invoke\\\\-WScriptBypassUAC* OR *PowerUp* OR *PowerView* OR *Get\\\\-RickAstley* OR *Find\\\\-Fruit* OR *HTTP\\\\-Login* OR *Find\\\\-TrustedDocuments* OR *Invoke\\\\-Paranoia* OR *Invoke\\\\-WinEnum* OR *Invoke\\\\-ARPScan* OR *Invoke\\\\-PortScan* OR *Invoke\\\\-ReverseDNSLookup* OR *Invoke\\\\-SMBScanner* OR *Invoke\\\\-Mimikittenz* OR *Invoke\\\\-AllChecks*) AND (NOT \\\\*.keyword:(*Get\\\\-SystemDriveInfo*)))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(Message.keyword:(*Invoke\\\\-DllInjection* OR *Invoke\\\\-Shellcode* OR *Invoke\\\\-WmiCommand* OR *Get\\\\-GPPPassword* OR *Get\\\\-Keystrokes* OR *Get\\\\-TimedScreenshot* OR *Get\\\\-VaultCredential* OR *Invoke\\\\-CredentialInjection* OR *Invoke\\\\-Mimikatz* OR *Invoke\\\\-NinjaCopy* OR *Invoke\\\\-TokenManipulation* OR *Out\\\\-Minidump* OR *VolumeShadowCopyTools* OR *Invoke\\\\-ReflectivePEInjection* OR *Invoke\\\\-UserHunter* OR *Find\\\\-GPOLocation* OR *Invoke\\\\-ACLScanner* OR *Invoke\\\\-DowngradeAccount* OR *Get\\\\-ServiceUnquoted* OR *Get\\\\-ServiceFilePermission* OR *Get\\\\-ServicePermission* OR *Invoke\\\\-ServiceAbuse* OR *Install\\\\-ServiceBinary* OR *Get\\\\-RegAutoLogon* OR *Get\\\\-VulnAutoRun* OR *Get\\\\-VulnSchTask* OR *Get\\\\-UnattendedInstallFile* OR *Get\\\\-ApplicationHost* OR *Get\\\\-RegAlwaysInstallElevated* OR *Get\\\\-Unconstrained* OR *Add\\\\-RegBackdoor* OR *Add\\\\-ScrnSaveBackdoor* OR *Gupt\\\\-Backdoor* OR *Invoke\\\\-ADSBackdoor* OR *Enabled\\\\-DuplicateToken* OR *Invoke\\\\-PsUaCme* OR *Remove\\\\-Update* OR *Check\\\\-VM* OR *Get\\\\-LSASecret* OR *Get\\\\-PassHashes* OR *Show\\\\-TargetScreen* OR *Port\\\\-Scan* OR *Invoke\\\\-PoshRatHttp* OR *Invoke\\\\-PowerShellTCP* OR *Invoke\\\\-PowerShellWMI* OR *Add\\\\-Exfiltration* OR *Add\\\\-Persistence* OR *Do\\\\-Exfiltration* OR *Start\\\\-CaptureServer* OR *Get\\\\-ChromeDump* OR *Get\\\\-ClipboardContents* OR *Get\\\\-FoxDump* OR *Get\\\\-IndexedItem* OR *Get\\\\-Screenshot* OR *Invoke\\\\-Inveigh* OR *Invoke\\\\-NetRipper* OR *Invoke\\\\-EgressCheck* OR *Invoke\\\\-PostExfil* OR *Invoke\\\\-PSInject* OR *Invoke\\\\-RunAs* OR *MailRaider* OR *New\\\\-HoneyHash* OR *Set\\\\-MacAttribute* OR *Invoke\\\\-DCSync* OR *Invoke\\\\-PowerDump* OR *Exploit\\\\-Jboss* OR *Invoke\\\\-ThunderStruck* OR *Invoke\\\\-VoiceTroll* OR *Set\\\\-Wallpaper* OR *Invoke\\\\-InveighRelay* OR *Invoke\\\\-PsExec* OR *Invoke\\\\-SSHCommand* OR *Get\\\\-SecurityPackages* OR *Install\\\\-SSP* OR *Invoke\\\\-BackdoorLNK* OR *PowerBreach* OR *Get\\\\-SiteListPassword* OR *Get\\\\-System* OR *Invoke\\\\-BypassUAC* OR *Invoke\\\\-Tater* OR *Invoke\\\\-WScriptBypassUAC* OR *PowerUp* OR *PowerView* OR *Get\\\\-RickAstley* OR *Find\\\\-Fruit* OR *HTTP\\\\-Login* OR *Find\\\\-TrustedDocuments* OR *Invoke\\\\-Paranoia* OR *Invoke\\\\-WinEnum* OR *Invoke\\\\-ARPScan* OR *Invoke\\\\-PortScan* OR *Invoke\\\\-ReverseDNSLookup* OR *Invoke\\\\-SMBScanner* OR *Invoke\\\\-Mimikittenz* OR *Invoke\\\\-AllChecks*) AND (NOT \\\\*.keyword:(*Get\\\\-SystemDriveInfo*)))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Malicious PowerShell Commandlets\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(Message.keyword:(*Invoke\\-DllInjection* *Invoke\\-Shellcode* *Invoke\\-WmiCommand* *Get\\-GPPPassword* *Get\\-Keystrokes* *Get\\-TimedScreenshot* *Get\\-VaultCredential* *Invoke\\-CredentialInjection* *Invoke\\-Mimikatz* *Invoke\\-NinjaCopy* *Invoke\\-TokenManipulation* *Out\\-Minidump* *VolumeShadowCopyTools* *Invoke\\-ReflectivePEInjection* *Invoke\\-UserHunter* *Find\\-GPOLocation* *Invoke\\-ACLScanner* *Invoke\\-DowngradeAccount* *Get\\-ServiceUnquoted* *Get\\-ServiceFilePermission* *Get\\-ServicePermission* *Invoke\\-ServiceAbuse* *Install\\-ServiceBinary* *Get\\-RegAutoLogon* *Get\\-VulnAutoRun* *Get\\-VulnSchTask* *Get\\-UnattendedInstallFile* *Get\\-ApplicationHost* *Get\\-RegAlwaysInstallElevated* *Get\\-Unconstrained* *Add\\-RegBackdoor* *Add\\-ScrnSaveBackdoor* *Gupt\\-Backdoor* *Invoke\\-ADSBackdoor* *Enabled\\-DuplicateToken* *Invoke\\-PsUaCme* *Remove\\-Update* *Check\\-VM* *Get\\-LSASecret* *Get\\-PassHashes* *Show\\-TargetScreen* *Port\\-Scan* *Invoke\\-PoshRatHttp* *Invoke\\-PowerShellTCP* *Invoke\\-PowerShellWMI* *Add\\-Exfiltration* *Add\\-Persistence* *Do\\-Exfiltration* *Start\\-CaptureServer* *Get\\-ChromeDump* *Get\\-ClipboardContents* *Get\\-FoxDump* *Get\\-IndexedItem* *Get\\-Screenshot* *Invoke\\-Inveigh* *Invoke\\-NetRipper* *Invoke\\-EgressCheck* *Invoke\\-PostExfil* *Invoke\\-PSInject* *Invoke\\-RunAs* *MailRaider* *New\\-HoneyHash* *Set\\-MacAttribute* *Invoke\\-DCSync* *Invoke\\-PowerDump* *Exploit\\-Jboss* *Invoke\\-ThunderStruck* *Invoke\\-VoiceTroll* *Set\\-Wallpaper* *Invoke\\-InveighRelay* *Invoke\\-PsExec* *Invoke\\-SSHCommand* *Get\\-SecurityPackages* *Install\\-SSP* *Invoke\\-BackdoorLNK* *PowerBreach* *Get\\-SiteListPassword* *Get\\-System* *Invoke\\-BypassUAC* *Invoke\\-Tater* *Invoke\\-WScriptBypassUAC* *PowerUp* *PowerView* *Get\\-RickAstley* *Find\\-Fruit* *HTTP\\-Login* *Find\\-TrustedDocuments* *Invoke\\-Paranoia* *Invoke\\-WinEnum* *Invoke\\-ARPScan* *Invoke\\-PortScan* *Invoke\\-ReverseDNSLookup* *Invoke\\-SMBScanner* *Invoke\\-Mimikittenz* *Invoke\\-AllChecks*) AND (NOT \\*.keyword:(*Get\\-SystemDriveInfo*)))
```


### splunk
    
```
((Message="*Invoke-DllInjection*" OR Message="*Invoke-Shellcode*" OR Message="*Invoke-WmiCommand*" OR Message="*Get-GPPPassword*" OR Message="*Get-Keystrokes*" OR Message="*Get-TimedScreenshot*" OR Message="*Get-VaultCredential*" OR Message="*Invoke-CredentialInjection*" OR Message="*Invoke-Mimikatz*" OR Message="*Invoke-NinjaCopy*" OR Message="*Invoke-TokenManipulation*" OR Message="*Out-Minidump*" OR Message="*VolumeShadowCopyTools*" OR Message="*Invoke-ReflectivePEInjection*" OR Message="*Invoke-UserHunter*" OR Message="*Find-GPOLocation*" OR Message="*Invoke-ACLScanner*" OR Message="*Invoke-DowngradeAccount*" OR Message="*Get-ServiceUnquoted*" OR Message="*Get-ServiceFilePermission*" OR Message="*Get-ServicePermission*" OR Message="*Invoke-ServiceAbuse*" OR Message="*Install-ServiceBinary*" OR Message="*Get-RegAutoLogon*" OR Message="*Get-VulnAutoRun*" OR Message="*Get-VulnSchTask*" OR Message="*Get-UnattendedInstallFile*" OR Message="*Get-ApplicationHost*" OR Message="*Get-RegAlwaysInstallElevated*" OR Message="*Get-Unconstrained*" OR Message="*Add-RegBackdoor*" OR Message="*Add-ScrnSaveBackdoor*" OR Message="*Gupt-Backdoor*" OR Message="*Invoke-ADSBackdoor*" OR Message="*Enabled-DuplicateToken*" OR Message="*Invoke-PsUaCme*" OR Message="*Remove-Update*" OR Message="*Check-VM*" OR Message="*Get-LSASecret*" OR Message="*Get-PassHashes*" OR Message="*Show-TargetScreen*" OR Message="*Port-Scan*" OR Message="*Invoke-PoshRatHttp*" OR Message="*Invoke-PowerShellTCP*" OR Message="*Invoke-PowerShellWMI*" OR Message="*Add-Exfiltration*" OR Message="*Add-Persistence*" OR Message="*Do-Exfiltration*" OR Message="*Start-CaptureServer*" OR Message="*Get-ChromeDump*" OR Message="*Get-ClipboardContents*" OR Message="*Get-FoxDump*" OR Message="*Get-IndexedItem*" OR Message="*Get-Screenshot*" OR Message="*Invoke-Inveigh*" OR Message="*Invoke-NetRipper*" OR Message="*Invoke-EgressCheck*" OR Message="*Invoke-PostExfil*" OR Message="*Invoke-PSInject*" OR Message="*Invoke-RunAs*" OR Message="*MailRaider*" OR Message="*New-HoneyHash*" OR Message="*Set-MacAttribute*" OR Message="*Invoke-DCSync*" OR Message="*Invoke-PowerDump*" OR Message="*Exploit-Jboss*" OR Message="*Invoke-ThunderStruck*" OR Message="*Invoke-VoiceTroll*" OR Message="*Set-Wallpaper*" OR Message="*Invoke-InveighRelay*" OR Message="*Invoke-PsExec*" OR Message="*Invoke-SSHCommand*" OR Message="*Get-SecurityPackages*" OR Message="*Install-SSP*" OR Message="*Invoke-BackdoorLNK*" OR Message="*PowerBreach*" OR Message="*Get-SiteListPassword*" OR Message="*Get-System*" OR Message="*Invoke-BypassUAC*" OR Message="*Invoke-Tater*" OR Message="*Invoke-WScriptBypassUAC*" OR Message="*PowerUp*" OR Message="*PowerView*" OR Message="*Get-RickAstley*" OR Message="*Find-Fruit*" OR Message="*HTTP-Login*" OR Message="*Find-TrustedDocuments*" OR Message="*Invoke-Paranoia*" OR Message="*Invoke-WinEnum*" OR Message="*Invoke-ARPScan*" OR Message="*Invoke-PortScan*" OR Message="*Invoke-ReverseDNSLookup*" OR Message="*Invoke-SMBScanner*" OR Message="*Invoke-Mimikittenz*" OR Message="*Invoke-AllChecks*") NOT ("Get-SystemDriveInfo"))
```


### logpoint
    
```
(Message IN ["*Invoke-DllInjection*", "*Invoke-Shellcode*", "*Invoke-WmiCommand*", "*Get-GPPPassword*", "*Get-Keystrokes*", "*Get-TimedScreenshot*", "*Get-VaultCredential*", "*Invoke-CredentialInjection*", "*Invoke-Mimikatz*", "*Invoke-NinjaCopy*", "*Invoke-TokenManipulation*", "*Out-Minidump*", "*VolumeShadowCopyTools*", "*Invoke-ReflectivePEInjection*", "*Invoke-UserHunter*", "*Find-GPOLocation*", "*Invoke-ACLScanner*", "*Invoke-DowngradeAccount*", "*Get-ServiceUnquoted*", "*Get-ServiceFilePermission*", "*Get-ServicePermission*", "*Invoke-ServiceAbuse*", "*Install-ServiceBinary*", "*Get-RegAutoLogon*", "*Get-VulnAutoRun*", "*Get-VulnSchTask*", "*Get-UnattendedInstallFile*", "*Get-ApplicationHost*", "*Get-RegAlwaysInstallElevated*", "*Get-Unconstrained*", "*Add-RegBackdoor*", "*Add-ScrnSaveBackdoor*", "*Gupt-Backdoor*", "*Invoke-ADSBackdoor*", "*Enabled-DuplicateToken*", "*Invoke-PsUaCme*", "*Remove-Update*", "*Check-VM*", "*Get-LSASecret*", "*Get-PassHashes*", "*Show-TargetScreen*", "*Port-Scan*", "*Invoke-PoshRatHttp*", "*Invoke-PowerShellTCP*", "*Invoke-PowerShellWMI*", "*Add-Exfiltration*", "*Add-Persistence*", "*Do-Exfiltration*", "*Start-CaptureServer*", "*Get-ChromeDump*", "*Get-ClipboardContents*", "*Get-FoxDump*", "*Get-IndexedItem*", "*Get-Screenshot*", "*Invoke-Inveigh*", "*Invoke-NetRipper*", "*Invoke-EgressCheck*", "*Invoke-PostExfil*", "*Invoke-PSInject*", "*Invoke-RunAs*", "*MailRaider*", "*New-HoneyHash*", "*Set-MacAttribute*", "*Invoke-DCSync*", "*Invoke-PowerDump*", "*Exploit-Jboss*", "*Invoke-ThunderStruck*", "*Invoke-VoiceTroll*", "*Set-Wallpaper*", "*Invoke-InveighRelay*", "*Invoke-PsExec*", "*Invoke-SSHCommand*", "*Get-SecurityPackages*", "*Install-SSP*", "*Invoke-BackdoorLNK*", "*PowerBreach*", "*Get-SiteListPassword*", "*Get-System*", "*Invoke-BypassUAC*", "*Invoke-Tater*", "*Invoke-WScriptBypassUAC*", "*PowerUp*", "*PowerView*", "*Get-RickAstley*", "*Find-Fruit*", "*HTTP-Login*", "*Find-TrustedDocuments*", "*Invoke-Paranoia*", "*Invoke-WinEnum*", "*Invoke-ARPScan*", "*Invoke-PortScan*", "*Invoke-ReverseDNSLookup*", "*Invoke-SMBScanner*", "*Invoke-Mimikittenz*", "*Invoke-AllChecks*"]  -("Get-SystemDriveInfo"))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*Invoke-DllInjection.*|.*.*Invoke-Shellcode.*|.*.*Invoke-WmiCommand.*|.*.*Get-GPPPassword.*|.*.*Get-Keystrokes.*|.*.*Get-TimedScreenshot.*|.*.*Get-VaultCredential.*|.*.*Invoke-CredentialInjection.*|.*.*Invoke-Mimikatz.*|.*.*Invoke-NinjaCopy.*|.*.*Invoke-TokenManipulation.*|.*.*Out-Minidump.*|.*.*VolumeShadowCopyTools.*|.*.*Invoke-ReflectivePEInjection.*|.*.*Invoke-UserHunter.*|.*.*Find-GPOLocation.*|.*.*Invoke-ACLScanner.*|.*.*Invoke-DowngradeAccount.*|.*.*Get-ServiceUnquoted.*|.*.*Get-ServiceFilePermission.*|.*.*Get-ServicePermission.*|.*.*Invoke-ServiceAbuse.*|.*.*Install-ServiceBinary.*|.*.*Get-RegAutoLogon.*|.*.*Get-VulnAutoRun.*|.*.*Get-VulnSchTask.*|.*.*Get-UnattendedInstallFile.*|.*.*Get-ApplicationHost.*|.*.*Get-RegAlwaysInstallElevated.*|.*.*Get-Unconstrained.*|.*.*Add-RegBackdoor.*|.*.*Add-ScrnSaveBackdoor.*|.*.*Gupt-Backdoor.*|.*.*Invoke-ADSBackdoor.*|.*.*Enabled-DuplicateToken.*|.*.*Invoke-PsUaCme.*|.*.*Remove-Update.*|.*.*Check-VM.*|.*.*Get-LSASecret.*|.*.*Get-PassHashes.*|.*.*Show-TargetScreen.*|.*.*Port-Scan.*|.*.*Invoke-PoshRatHttp.*|.*.*Invoke-PowerShellTCP.*|.*.*Invoke-PowerShellWMI.*|.*.*Add-Exfiltration.*|.*.*Add-Persistence.*|.*.*Do-Exfiltration.*|.*.*Start-CaptureServer.*|.*.*Get-ChromeDump.*|.*.*Get-ClipboardContents.*|.*.*Get-FoxDump.*|.*.*Get-IndexedItem.*|.*.*Get-Screenshot.*|.*.*Invoke-Inveigh.*|.*.*Invoke-NetRipper.*|.*.*Invoke-EgressCheck.*|.*.*Invoke-PostExfil.*|.*.*Invoke-PSInject.*|.*.*Invoke-RunAs.*|.*.*MailRaider.*|.*.*New-HoneyHash.*|.*.*Set-MacAttribute.*|.*.*Invoke-DCSync.*|.*.*Invoke-PowerDump.*|.*.*Exploit-Jboss.*|.*.*Invoke-ThunderStruck.*|.*.*Invoke-VoiceTroll.*|.*.*Set-Wallpaper.*|.*.*Invoke-InveighRelay.*|.*.*Invoke-PsExec.*|.*.*Invoke-SSHCommand.*|.*.*Get-SecurityPackages.*|.*.*Install-SSP.*|.*.*Invoke-BackdoorLNK.*|.*.*PowerBreach.*|.*.*Get-SiteListPassword.*|.*.*Get-System.*|.*.*Invoke-BypassUAC.*|.*.*Invoke-Tater.*|.*.*Invoke-WScriptBypassUAC.*|.*.*PowerUp.*|.*.*PowerView.*|.*.*Get-RickAstley.*|.*.*Find-Fruit.*|.*.*HTTP-Login.*|.*.*Find-TrustedDocuments.*|.*.*Invoke-Paranoia.*|.*.*Invoke-WinEnum.*|.*.*Invoke-ARPScan.*|.*.*Invoke-PortScan.*|.*.*Invoke-ReverseDNSLookup.*|.*.*Invoke-SMBScanner.*|.*.*Invoke-Mimikittenz.*|.*.*Invoke-AllChecks.*))(?=.*(?!.*(?:.*(?:.*Get-SystemDriveInfo)))))'
```



