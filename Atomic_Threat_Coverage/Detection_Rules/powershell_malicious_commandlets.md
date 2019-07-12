| Title                | Malicious PowerShell Commandlets                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects Commandlet names from well-known PowerShell exploitation frameworks                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| Data Needed          | <ul><li>[DN_0036_4104_windows_powershell_script_block](../Data_Needed/DN_0036_4104_windows_powershell_script_block.md)</li><li>[DN_0037_4103_windows_powershell_executing_pipeline](../Data_Needed/DN_0037_4103_windows_powershell_executing_pipeline.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Penetration testing</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://adsecurity.org/?p=2921](https://adsecurity.org/?p=2921)</li></ul>  |
| Author               | Sean Metcalf (source), Florian Roth (rule) |


## Detection Rules

### Sigma rule

```
title: Malicious PowerShell Commandlets
status: experimental
description: Detects Commandlet names from well-known PowerShell exploitation frameworks
modified: 2019/01/22
references:
    - https://adsecurity.org/?p=2921
tags:
    - attack.execution
    - attack.t1086
author: Sean Metcalf (source), Florian Roth (rule)
logsource:
    product: windows
    service: powershell
    definition: 'It is recommended to use the new "Script Block Logging" of PowerShell v5 https://adsecurity.org/?p=2277'
detection:
    keywords:
        - Invoke-DllInjection
        - Invoke-Shellcode
        - Invoke-WmiCommand
        - Get-GPPPassword
        - Get-Keystrokes
        - Get-TimedScreenshot
        - Get-VaultCredential
        - Invoke-CredentialInjection
        - Invoke-Mimikatz
        - Invoke-NinjaCopy
        - Invoke-TokenManipulation
        - Out-Minidump
        - VolumeShadowCopyTools
        - Invoke-ReflectivePEInjection
        - Invoke-UserHunter
        - Find-GPOLocation
        - Invoke-ACLScanner
        - Invoke-DowngradeAccount
        - Get-ServiceUnquoted
        - Get-ServiceFilePermission
        - Get-ServicePermission
        - Invoke-ServiceAbuse
        - Install-ServiceBinary
        - Get-RegAutoLogon
        - Get-VulnAutoRun
        - Get-VulnSchTask
        - Get-UnattendedInstallFile
        - Get-ApplicationHost
        - Get-RegAlwaysInstallElevated
        - Get-Unconstrained
        - Add-RegBackdoor
        - Add-ScrnSaveBackdoor
        - Gupt-Backdoor
        - Invoke-ADSBackdoor
        - Enabled-DuplicateToken
        - Invoke-PsUaCme
        - Remove-Update
        - Check-VM
        - Get-LSASecret
        - Get-PassHashes
        - Show-TargetScreen
        - Port-Scan
        - Invoke-PoshRatHttp
        - Invoke-PowerShellTCP
        - Invoke-PowerShellWMI
        - Add-Exfiltration
        - Add-Persistence
        - Do-Exfiltration
        - Start-CaptureServer
        - Get-ChromeDump
        - Get-ClipboardContents
        - Get-FoxDump
        - Get-IndexedItem
        - Get-Screenshot
        - Invoke-Inveigh
        - Invoke-NetRipper
        - Invoke-EgressCheck
        - Invoke-PostExfil
        - Invoke-PSInject
        - Invoke-RunAs
        - MailRaider
        - New-HoneyHash
        - Set-MacAttribute
        - Invoke-DCSync
        - Invoke-PowerDump
        - Exploit-Jboss
        - Invoke-ThunderStruck
        - Invoke-VoiceTroll
        - Set-Wallpaper
        - Invoke-InveighRelay
        - Invoke-PsExec
        - Invoke-SSHCommand
        - Get-SecurityPackages
        - Install-SSP
        - Invoke-BackdoorLNK
        - PowerBreach
        - Get-SiteListPassword
        - Get-System
        - Invoke-BypassUAC
        - Invoke-Tater
        - Invoke-WScriptBypassUAC
        - PowerUp
        - PowerView
        - Get-RickAstley
        - Find-Fruit
        - HTTP-Login
        - Find-TrustedDocuments
        - Invoke-Paranoia
        - Invoke-WinEnum
        - Invoke-ARPScan
        - Invoke-PortScan
        - Invoke-ReverseDNSLookup
        - Invoke-SMBScanner
        - Invoke-Mimikittenz
    condition: keywords
falsepositives:
    - Penetration testing
level: high

```





### es-qs
    
```
(Invoke\\-DllInjection OR Invoke\\-Shellcode OR Invoke\\-WmiCommand OR Get\\-GPPPassword OR Get\\-Keystrokes OR Get\\-TimedScreenshot OR Get\\-VaultCredential OR Invoke\\-CredentialInjection OR Invoke\\-Mimikatz OR Invoke\\-NinjaCopy OR Invoke\\-TokenManipulation OR Out\\-Minidump OR VolumeShadowCopyTools OR Invoke\\-ReflectivePEInjection OR Invoke\\-UserHunter OR Find\\-GPOLocation OR Invoke\\-ACLScanner OR Invoke\\-DowngradeAccount OR Get\\-ServiceUnquoted OR Get\\-ServiceFilePermission OR Get\\-ServicePermission OR Invoke\\-ServiceAbuse OR Install\\-ServiceBinary OR Get\\-RegAutoLogon OR Get\\-VulnAutoRun OR Get\\-VulnSchTask OR Get\\-UnattendedInstallFile OR Get\\-ApplicationHost OR Get\\-RegAlwaysInstallElevated OR Get\\-Unconstrained OR Add\\-RegBackdoor OR Add\\-ScrnSaveBackdoor OR Gupt\\-Backdoor OR Invoke\\-ADSBackdoor OR Enabled\\-DuplicateToken OR Invoke\\-PsUaCme OR Remove\\-Update OR Check\\-VM OR Get\\-LSASecret OR Get\\-PassHashes OR Show\\-TargetScreen OR Port\\-Scan OR Invoke\\-PoshRatHttp OR Invoke\\-PowerShellTCP OR Invoke\\-PowerShellWMI OR Add\\-Exfiltration OR Add\\-Persistence OR Do\\-Exfiltration OR Start\\-CaptureServer OR Get\\-ChromeDump OR Get\\-ClipboardContents OR Get\\-FoxDump OR Get\\-IndexedItem OR Get\\-Screenshot OR Invoke\\-Inveigh OR Invoke\\-NetRipper OR Invoke\\-EgressCheck OR Invoke\\-PostExfil OR Invoke\\-PSInject OR Invoke\\-RunAs OR MailRaider OR New\\-HoneyHash OR Set\\-MacAttribute OR Invoke\\-DCSync OR Invoke\\-PowerDump OR Exploit\\-Jboss OR Invoke\\-ThunderStruck OR Invoke\\-VoiceTroll OR Set\\-Wallpaper OR Invoke\\-InveighRelay OR Invoke\\-PsExec OR Invoke\\-SSHCommand OR Get\\-SecurityPackages OR Install\\-SSP OR Invoke\\-BackdoorLNK OR PowerBreach OR Get\\-SiteListPassword OR Get\\-System OR Invoke\\-BypassUAC OR Invoke\\-Tater OR Invoke\\-WScriptBypassUAC OR PowerUp OR PowerView OR Get\\-RickAstley OR Find\\-Fruit OR HTTP\\-Login OR Find\\-TrustedDocuments OR Invoke\\-Paranoia OR Invoke\\-WinEnum OR Invoke\\-ARPScan OR Invoke\\-PortScan OR Invoke\\-ReverseDNSLookup OR Invoke\\-SMBScanner OR Invoke\\-Mimikittenz)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Malicious-PowerShell-Commandlets <<EOF\n{\n  "metadata": {\n    "title": "Malicious PowerShell Commandlets",\n    "description": "Detects Commandlet names from well-known PowerShell exploitation frameworks",\n    "tags": [\n      "attack.execution",\n      "attack.t1086"\n    ],\n    "query": "(Invoke\\\\-DllInjection OR Invoke\\\\-Shellcode OR Invoke\\\\-WmiCommand OR Get\\\\-GPPPassword OR Get\\\\-Keystrokes OR Get\\\\-TimedScreenshot OR Get\\\\-VaultCredential OR Invoke\\\\-CredentialInjection OR Invoke\\\\-Mimikatz OR Invoke\\\\-NinjaCopy OR Invoke\\\\-TokenManipulation OR Out\\\\-Minidump OR VolumeShadowCopyTools OR Invoke\\\\-ReflectivePEInjection OR Invoke\\\\-UserHunter OR Find\\\\-GPOLocation OR Invoke\\\\-ACLScanner OR Invoke\\\\-DowngradeAccount OR Get\\\\-ServiceUnquoted OR Get\\\\-ServiceFilePermission OR Get\\\\-ServicePermission OR Invoke\\\\-ServiceAbuse OR Install\\\\-ServiceBinary OR Get\\\\-RegAutoLogon OR Get\\\\-VulnAutoRun OR Get\\\\-VulnSchTask OR Get\\\\-UnattendedInstallFile OR Get\\\\-ApplicationHost OR Get\\\\-RegAlwaysInstallElevated OR Get\\\\-Unconstrained OR Add\\\\-RegBackdoor OR Add\\\\-ScrnSaveBackdoor OR Gupt\\\\-Backdoor OR Invoke\\\\-ADSBackdoor OR Enabled\\\\-DuplicateToken OR Invoke\\\\-PsUaCme OR Remove\\\\-Update OR Check\\\\-VM OR Get\\\\-LSASecret OR Get\\\\-PassHashes OR Show\\\\-TargetScreen OR Port\\\\-Scan OR Invoke\\\\-PoshRatHttp OR Invoke\\\\-PowerShellTCP OR Invoke\\\\-PowerShellWMI OR Add\\\\-Exfiltration OR Add\\\\-Persistence OR Do\\\\-Exfiltration OR Start\\\\-CaptureServer OR Get\\\\-ChromeDump OR Get\\\\-ClipboardContents OR Get\\\\-FoxDump OR Get\\\\-IndexedItem OR Get\\\\-Screenshot OR Invoke\\\\-Inveigh OR Invoke\\\\-NetRipper OR Invoke\\\\-EgressCheck OR Invoke\\\\-PostExfil OR Invoke\\\\-PSInject OR Invoke\\\\-RunAs OR MailRaider OR New\\\\-HoneyHash OR Set\\\\-MacAttribute OR Invoke\\\\-DCSync OR Invoke\\\\-PowerDump OR Exploit\\\\-Jboss OR Invoke\\\\-ThunderStruck OR Invoke\\\\-VoiceTroll OR Set\\\\-Wallpaper OR Invoke\\\\-InveighRelay OR Invoke\\\\-PsExec OR Invoke\\\\-SSHCommand OR Get\\\\-SecurityPackages OR Install\\\\-SSP OR Invoke\\\\-BackdoorLNK OR PowerBreach OR Get\\\\-SiteListPassword OR Get\\\\-System OR Invoke\\\\-BypassUAC OR Invoke\\\\-Tater OR Invoke\\\\-WScriptBypassUAC OR PowerUp OR PowerView OR Get\\\\-RickAstley OR Find\\\\-Fruit OR HTTP\\\\-Login OR Find\\\\-TrustedDocuments OR Invoke\\\\-Paranoia OR Invoke\\\\-WinEnum OR Invoke\\\\-ARPScan OR Invoke\\\\-PortScan OR Invoke\\\\-ReverseDNSLookup OR Invoke\\\\-SMBScanner OR Invoke\\\\-Mimikittenz)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(Invoke\\\\-DllInjection OR Invoke\\\\-Shellcode OR Invoke\\\\-WmiCommand OR Get\\\\-GPPPassword OR Get\\\\-Keystrokes OR Get\\\\-TimedScreenshot OR Get\\\\-VaultCredential OR Invoke\\\\-CredentialInjection OR Invoke\\\\-Mimikatz OR Invoke\\\\-NinjaCopy OR Invoke\\\\-TokenManipulation OR Out\\\\-Minidump OR VolumeShadowCopyTools OR Invoke\\\\-ReflectivePEInjection OR Invoke\\\\-UserHunter OR Find\\\\-GPOLocation OR Invoke\\\\-ACLScanner OR Invoke\\\\-DowngradeAccount OR Get\\\\-ServiceUnquoted OR Get\\\\-ServiceFilePermission OR Get\\\\-ServicePermission OR Invoke\\\\-ServiceAbuse OR Install\\\\-ServiceBinary OR Get\\\\-RegAutoLogon OR Get\\\\-VulnAutoRun OR Get\\\\-VulnSchTask OR Get\\\\-UnattendedInstallFile OR Get\\\\-ApplicationHost OR Get\\\\-RegAlwaysInstallElevated OR Get\\\\-Unconstrained OR Add\\\\-RegBackdoor OR Add\\\\-ScrnSaveBackdoor OR Gupt\\\\-Backdoor OR Invoke\\\\-ADSBackdoor OR Enabled\\\\-DuplicateToken OR Invoke\\\\-PsUaCme OR Remove\\\\-Update OR Check\\\\-VM OR Get\\\\-LSASecret OR Get\\\\-PassHashes OR Show\\\\-TargetScreen OR Port\\\\-Scan OR Invoke\\\\-PoshRatHttp OR Invoke\\\\-PowerShellTCP OR Invoke\\\\-PowerShellWMI OR Add\\\\-Exfiltration OR Add\\\\-Persistence OR Do\\\\-Exfiltration OR Start\\\\-CaptureServer OR Get\\\\-ChromeDump OR Get\\\\-ClipboardContents OR Get\\\\-FoxDump OR Get\\\\-IndexedItem OR Get\\\\-Screenshot OR Invoke\\\\-Inveigh OR Invoke\\\\-NetRipper OR Invoke\\\\-EgressCheck OR Invoke\\\\-PostExfil OR Invoke\\\\-PSInject OR Invoke\\\\-RunAs OR MailRaider OR New\\\\-HoneyHash OR Set\\\\-MacAttribute OR Invoke\\\\-DCSync OR Invoke\\\\-PowerDump OR Exploit\\\\-Jboss OR Invoke\\\\-ThunderStruck OR Invoke\\\\-VoiceTroll OR Set\\\\-Wallpaper OR Invoke\\\\-InveighRelay OR Invoke\\\\-PsExec OR Invoke\\\\-SSHCommand OR Get\\\\-SecurityPackages OR Install\\\\-SSP OR Invoke\\\\-BackdoorLNK OR PowerBreach OR Get\\\\-SiteListPassword OR Get\\\\-System OR Invoke\\\\-BypassUAC OR Invoke\\\\-Tater OR Invoke\\\\-WScriptBypassUAC OR PowerUp OR PowerView OR Get\\\\-RickAstley OR Find\\\\-Fruit OR HTTP\\\\-Login OR Find\\\\-TrustedDocuments OR Invoke\\\\-Paranoia OR Invoke\\\\-WinEnum OR Invoke\\\\-ARPScan OR Invoke\\\\-PortScan OR Invoke\\\\-ReverseDNSLookup OR Invoke\\\\-SMBScanner OR Invoke\\\\-Mimikittenz)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Malicious PowerShell Commandlets\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
("Invoke\\-DllInjection" OR "Invoke\\-Shellcode" OR "Invoke\\-WmiCommand" OR "Get\\-GPPPassword" OR "Get\\-Keystrokes" OR "Get\\-TimedScreenshot" OR "Get\\-VaultCredential" OR "Invoke\\-CredentialInjection" OR "Invoke\\-Mimikatz" OR "Invoke\\-NinjaCopy" OR "Invoke\\-TokenManipulation" OR "Out\\-Minidump" OR "VolumeShadowCopyTools" OR "Invoke\\-ReflectivePEInjection" OR "Invoke\\-UserHunter" OR "Find\\-GPOLocation" OR "Invoke\\-ACLScanner" OR "Invoke\\-DowngradeAccount" OR "Get\\-ServiceUnquoted" OR "Get\\-ServiceFilePermission" OR "Get\\-ServicePermission" OR "Invoke\\-ServiceAbuse" OR "Install\\-ServiceBinary" OR "Get\\-RegAutoLogon" OR "Get\\-VulnAutoRun" OR "Get\\-VulnSchTask" OR "Get\\-UnattendedInstallFile" OR "Get\\-ApplicationHost" OR "Get\\-RegAlwaysInstallElevated" OR "Get\\-Unconstrained" OR "Add\\-RegBackdoor" OR "Add\\-ScrnSaveBackdoor" OR "Gupt\\-Backdoor" OR "Invoke\\-ADSBackdoor" OR "Enabled\\-DuplicateToken" OR "Invoke\\-PsUaCme" OR "Remove\\-Update" OR "Check\\-VM" OR "Get\\-LSASecret" OR "Get\\-PassHashes" OR "Show\\-TargetScreen" OR "Port\\-Scan" OR "Invoke\\-PoshRatHttp" OR "Invoke\\-PowerShellTCP" OR "Invoke\\-PowerShellWMI" OR "Add\\-Exfiltration" OR "Add\\-Persistence" OR "Do\\-Exfiltration" OR "Start\\-CaptureServer" OR "Get\\-ChromeDump" OR "Get\\-ClipboardContents" OR "Get\\-FoxDump" OR "Get\\-IndexedItem" OR "Get\\-Screenshot" OR "Invoke\\-Inveigh" OR "Invoke\\-NetRipper" OR "Invoke\\-EgressCheck" OR "Invoke\\-PostExfil" OR "Invoke\\-PSInject" OR "Invoke\\-RunAs" OR "MailRaider" OR "New\\-HoneyHash" OR "Set\\-MacAttribute" OR "Invoke\\-DCSync" OR "Invoke\\-PowerDump" OR "Exploit\\-Jboss" OR "Invoke\\-ThunderStruck" OR "Invoke\\-VoiceTroll" OR "Set\\-Wallpaper" OR "Invoke\\-InveighRelay" OR "Invoke\\-PsExec" OR "Invoke\\-SSHCommand" OR "Get\\-SecurityPackages" OR "Install\\-SSP" OR "Invoke\\-BackdoorLNK" OR "PowerBreach" OR "Get\\-SiteListPassword" OR "Get\\-System" OR "Invoke\\-BypassUAC" OR "Invoke\\-Tater" OR "Invoke\\-WScriptBypassUAC" OR "PowerUp" OR "PowerView" OR "Get\\-RickAstley" OR "Find\\-Fruit" OR "HTTP\\-Login" OR "Find\\-TrustedDocuments" OR "Invoke\\-Paranoia" OR "Invoke\\-WinEnum" OR "Invoke\\-ARPScan" OR "Invoke\\-PortScan" OR "Invoke\\-ReverseDNSLookup" OR "Invoke\\-SMBScanner" OR "Invoke\\-Mimikittenz")
```


### splunk
    
```
("Invoke-DllInjection" OR "Invoke-Shellcode" OR "Invoke-WmiCommand" OR "Get-GPPPassword" OR "Get-Keystrokes" OR "Get-TimedScreenshot" OR "Get-VaultCredential" OR "Invoke-CredentialInjection" OR "Invoke-Mimikatz" OR "Invoke-NinjaCopy" OR "Invoke-TokenManipulation" OR "Out-Minidump" OR "VolumeShadowCopyTools" OR "Invoke-ReflectivePEInjection" OR "Invoke-UserHunter" OR "Find-GPOLocation" OR "Invoke-ACLScanner" OR "Invoke-DowngradeAccount" OR "Get-ServiceUnquoted" OR "Get-ServiceFilePermission" OR "Get-ServicePermission" OR "Invoke-ServiceAbuse" OR "Install-ServiceBinary" OR "Get-RegAutoLogon" OR "Get-VulnAutoRun" OR "Get-VulnSchTask" OR "Get-UnattendedInstallFile" OR "Get-ApplicationHost" OR "Get-RegAlwaysInstallElevated" OR "Get-Unconstrained" OR "Add-RegBackdoor" OR "Add-ScrnSaveBackdoor" OR "Gupt-Backdoor" OR "Invoke-ADSBackdoor" OR "Enabled-DuplicateToken" OR "Invoke-PsUaCme" OR "Remove-Update" OR "Check-VM" OR "Get-LSASecret" OR "Get-PassHashes" OR "Show-TargetScreen" OR "Port-Scan" OR "Invoke-PoshRatHttp" OR "Invoke-PowerShellTCP" OR "Invoke-PowerShellWMI" OR "Add-Exfiltration" OR "Add-Persistence" OR "Do-Exfiltration" OR "Start-CaptureServer" OR "Get-ChromeDump" OR "Get-ClipboardContents" OR "Get-FoxDump" OR "Get-IndexedItem" OR "Get-Screenshot" OR "Invoke-Inveigh" OR "Invoke-NetRipper" OR "Invoke-EgressCheck" OR "Invoke-PostExfil" OR "Invoke-PSInject" OR "Invoke-RunAs" OR "MailRaider" OR "New-HoneyHash" OR "Set-MacAttribute" OR "Invoke-DCSync" OR "Invoke-PowerDump" OR "Exploit-Jboss" OR "Invoke-ThunderStruck" OR "Invoke-VoiceTroll" OR "Set-Wallpaper" OR "Invoke-InveighRelay" OR "Invoke-PsExec" OR "Invoke-SSHCommand" OR "Get-SecurityPackages" OR "Install-SSP" OR "Invoke-BackdoorLNK" OR "PowerBreach" OR "Get-SiteListPassword" OR "Get-System" OR "Invoke-BypassUAC" OR "Invoke-Tater" OR "Invoke-WScriptBypassUAC" OR "PowerUp" OR "PowerView" OR "Get-RickAstley" OR "Find-Fruit" OR "HTTP-Login" OR "Find-TrustedDocuments" OR "Invoke-Paranoia" OR "Invoke-WinEnum" OR "Invoke-ARPScan" OR "Invoke-PortScan" OR "Invoke-ReverseDNSLookup" OR "Invoke-SMBScanner" OR "Invoke-Mimikittenz")
```


### logpoint
    
```
("Invoke-DllInjection" OR "Invoke-Shellcode" OR "Invoke-WmiCommand" OR "Get-GPPPassword" OR "Get-Keystrokes" OR "Get-TimedScreenshot" OR "Get-VaultCredential" OR "Invoke-CredentialInjection" OR "Invoke-Mimikatz" OR "Invoke-NinjaCopy" OR "Invoke-TokenManipulation" OR "Out-Minidump" OR "VolumeShadowCopyTools" OR "Invoke-ReflectivePEInjection" OR "Invoke-UserHunter" OR "Find-GPOLocation" OR "Invoke-ACLScanner" OR "Invoke-DowngradeAccount" OR "Get-ServiceUnquoted" OR "Get-ServiceFilePermission" OR "Get-ServicePermission" OR "Invoke-ServiceAbuse" OR "Install-ServiceBinary" OR "Get-RegAutoLogon" OR "Get-VulnAutoRun" OR "Get-VulnSchTask" OR "Get-UnattendedInstallFile" OR "Get-ApplicationHost" OR "Get-RegAlwaysInstallElevated" OR "Get-Unconstrained" OR "Add-RegBackdoor" OR "Add-ScrnSaveBackdoor" OR "Gupt-Backdoor" OR "Invoke-ADSBackdoor" OR "Enabled-DuplicateToken" OR "Invoke-PsUaCme" OR "Remove-Update" OR "Check-VM" OR "Get-LSASecret" OR "Get-PassHashes" OR "Show-TargetScreen" OR "Port-Scan" OR "Invoke-PoshRatHttp" OR "Invoke-PowerShellTCP" OR "Invoke-PowerShellWMI" OR "Add-Exfiltration" OR "Add-Persistence" OR "Do-Exfiltration" OR "Start-CaptureServer" OR "Get-ChromeDump" OR "Get-ClipboardContents" OR "Get-FoxDump" OR "Get-IndexedItem" OR "Get-Screenshot" OR "Invoke-Inveigh" OR "Invoke-NetRipper" OR "Invoke-EgressCheck" OR "Invoke-PostExfil" OR "Invoke-PSInject" OR "Invoke-RunAs" OR "MailRaider" OR "New-HoneyHash" OR "Set-MacAttribute" OR "Invoke-DCSync" OR "Invoke-PowerDump" OR "Exploit-Jboss" OR "Invoke-ThunderStruck" OR "Invoke-VoiceTroll" OR "Set-Wallpaper" OR "Invoke-InveighRelay" OR "Invoke-PsExec" OR "Invoke-SSHCommand" OR "Get-SecurityPackages" OR "Install-SSP" OR "Invoke-BackdoorLNK" OR "PowerBreach" OR "Get-SiteListPassword" OR "Get-System" OR "Invoke-BypassUAC" OR "Invoke-Tater" OR "Invoke-WScriptBypassUAC" OR "PowerUp" OR "PowerView" OR "Get-RickAstley" OR "Find-Fruit" OR "HTTP-Login" OR "Find-TrustedDocuments" OR "Invoke-Paranoia" OR "Invoke-WinEnum" OR "Invoke-ARPScan" OR "Invoke-PortScan" OR "Invoke-ReverseDNSLookup" OR "Invoke-SMBScanner" OR "Invoke-Mimikittenz")
```


### grep
    
```
grep -P '^(?:.*(?:.*Invoke-DllInjection|.*Invoke-Shellcode|.*Invoke-WmiCommand|.*Get-GPPPassword|.*Get-Keystrokes|.*Get-TimedScreenshot|.*Get-VaultCredential|.*Invoke-CredentialInjection|.*Invoke-Mimikatz|.*Invoke-NinjaCopy|.*Invoke-TokenManipulation|.*Out-Minidump|.*VolumeShadowCopyTools|.*Invoke-ReflectivePEInjection|.*Invoke-UserHunter|.*Find-GPOLocation|.*Invoke-ACLScanner|.*Invoke-DowngradeAccount|.*Get-ServiceUnquoted|.*Get-ServiceFilePermission|.*Get-ServicePermission|.*Invoke-ServiceAbuse|.*Install-ServiceBinary|.*Get-RegAutoLogon|.*Get-VulnAutoRun|.*Get-VulnSchTask|.*Get-UnattendedInstallFile|.*Get-ApplicationHost|.*Get-RegAlwaysInstallElevated|.*Get-Unconstrained|.*Add-RegBackdoor|.*Add-ScrnSaveBackdoor|.*Gupt-Backdoor|.*Invoke-ADSBackdoor|.*Enabled-DuplicateToken|.*Invoke-PsUaCme|.*Remove-Update|.*Check-VM|.*Get-LSASecret|.*Get-PassHashes|.*Show-TargetScreen|.*Port-Scan|.*Invoke-PoshRatHttp|.*Invoke-PowerShellTCP|.*Invoke-PowerShellWMI|.*Add-Exfiltration|.*Add-Persistence|.*Do-Exfiltration|.*Start-CaptureServer|.*Get-ChromeDump|.*Get-ClipboardContents|.*Get-FoxDump|.*Get-IndexedItem|.*Get-Screenshot|.*Invoke-Inveigh|.*Invoke-NetRipper|.*Invoke-EgressCheck|.*Invoke-PostExfil|.*Invoke-PSInject|.*Invoke-RunAs|.*MailRaider|.*New-HoneyHash|.*Set-MacAttribute|.*Invoke-DCSync|.*Invoke-PowerDump|.*Exploit-Jboss|.*Invoke-ThunderStruck|.*Invoke-VoiceTroll|.*Set-Wallpaper|.*Invoke-InveighRelay|.*Invoke-PsExec|.*Invoke-SSHCommand|.*Get-SecurityPackages|.*Install-SSP|.*Invoke-BackdoorLNK|.*PowerBreach|.*Get-SiteListPassword|.*Get-System|.*Invoke-BypassUAC|.*Invoke-Tater|.*Invoke-WScriptBypassUAC|.*PowerUp|.*PowerView|.*Get-RickAstley|.*Find-Fruit|.*HTTP-Login|.*Find-TrustedDocuments|.*Invoke-Paranoia|.*Invoke-WinEnum|.*Invoke-ARPScan|.*Invoke-PortScan|.*Invoke-ReverseDNSLookup|.*Invoke-SMBScanner|.*Invoke-Mimikittenz))'
```



