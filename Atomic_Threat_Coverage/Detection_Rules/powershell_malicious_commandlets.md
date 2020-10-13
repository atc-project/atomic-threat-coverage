| Title                    | Malicious PowerShell Commandlets       |
|:-------------------------|:------------------|
| **Description**          | Detects Commandlet names from well-known PowerShell exploitation frameworks |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1059.001: PowerShell](https://attack.mitre.org/techniques/T1059/001)</li><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              | <ul><li>[T1059.001: PowerShell](../Triggers/T1059.001.md)</li></ul>  |
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
references:
    - https://adsecurity.org/?p=2921
tags:
    - attack.execution
    - attack.t1059.001
    - attack.t1086  #an old one
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





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {(($_.message -match ".*Invoke-DllInjection.*" -or $_.message -match ".*Invoke-Shellcode.*" -or $_.message -match ".*Invoke-WmiCommand.*" -or $_.message -match ".*Get-GPPPassword.*" -or $_.message -match ".*Get-Keystrokes.*" -or $_.message -match ".*Get-TimedScreenshot.*" -or $_.message -match ".*Get-VaultCredential.*" -or $_.message -match ".*Invoke-CredentialInjection.*" -or $_.message -match ".*Invoke-Mimikatz.*" -or $_.message -match ".*Invoke-NinjaCopy.*" -or $_.message -match ".*Invoke-TokenManipulation.*" -or $_.message -match ".*Out-Minidump.*" -or $_.message -match ".*VolumeShadowCopyTools.*" -or $_.message -match ".*Invoke-ReflectivePEInjection.*" -or $_.message -match ".*Invoke-UserHunter.*" -or $_.message -match ".*Find-GPOLocation.*" -or $_.message -match ".*Invoke-ACLScanner.*" -or $_.message -match ".*Invoke-DowngradeAccount.*" -or $_.message -match ".*Get-ServiceUnquoted.*" -or $_.message -match ".*Get-ServiceFilePermission.*" -or $_.message -match ".*Get-ServicePermission.*" -or $_.message -match ".*Invoke-ServiceAbuse.*" -or $_.message -match ".*Install-ServiceBinary.*" -or $_.message -match ".*Get-RegAutoLogon.*" -or $_.message -match ".*Get-VulnAutoRun.*" -or $_.message -match ".*Get-VulnSchTask.*" -or $_.message -match ".*Get-UnattendedInstallFile.*" -or $_.message -match ".*Get-ApplicationHost.*" -or $_.message -match ".*Get-RegAlwaysInstallElevated.*" -or $_.message -match ".*Get-Unconstrained.*" -or $_.message -match ".*Add-RegBackdoor.*" -or $_.message -match ".*Add-ScrnSaveBackdoor.*" -or $_.message -match ".*Gupt-Backdoor.*" -or $_.message -match ".*Invoke-ADSBackdoor.*" -or $_.message -match ".*Enabled-DuplicateToken.*" -or $_.message -match ".*Invoke-PsUaCme.*" -or $_.message -match ".*Remove-Update.*" -or $_.message -match ".*Check-VM.*" -or $_.message -match ".*Get-LSASecret.*" -or $_.message -match ".*Get-PassHashes.*" -or $_.message -match ".*Show-TargetScreen.*" -or $_.message -match ".*Port-Scan.*" -or $_.message -match ".*Invoke-PoshRatHttp.*" -or $_.message -match ".*Invoke-PowerShellTCP.*" -or $_.message -match ".*Invoke-PowerShellWMI.*" -or $_.message -match ".*Add-Exfiltration.*" -or $_.message -match ".*Add-Persistence.*" -or $_.message -match ".*Do-Exfiltration.*" -or $_.message -match ".*Start-CaptureServer.*" -or $_.message -match ".*Get-ChromeDump.*" -or $_.message -match ".*Get-ClipboardContents.*" -or $_.message -match ".*Get-FoxDump.*" -or $_.message -match ".*Get-IndexedItem.*" -or $_.message -match ".*Get-Screenshot.*" -or $_.message -match ".*Invoke-Inveigh.*" -or $_.message -match ".*Invoke-NetRipper.*" -or $_.message -match ".*Invoke-EgressCheck.*" -or $_.message -match ".*Invoke-PostExfil.*" -or $_.message -match ".*Invoke-PSInject.*" -or $_.message -match ".*Invoke-RunAs.*" -or $_.message -match ".*MailRaider.*" -or $_.message -match ".*New-HoneyHash.*" -or $_.message -match ".*Set-MacAttribute.*" -or $_.message -match ".*Invoke-DCSync.*" -or $_.message -match ".*Invoke-PowerDump.*" -or $_.message -match ".*Exploit-Jboss.*" -or $_.message -match ".*Invoke-ThunderStruck.*" -or $_.message -match ".*Invoke-VoiceTroll.*" -or $_.message -match ".*Set-Wallpaper.*" -or $_.message -match ".*Invoke-InveighRelay.*" -or $_.message -match ".*Invoke-PsExec.*" -or $_.message -match ".*Invoke-SSHCommand.*" -or $_.message -match ".*Get-SecurityPackages.*" -or $_.message -match ".*Install-SSP.*" -or $_.message -match ".*Invoke-BackdoorLNK.*" -or $_.message -match ".*PowerBreach.*" -or $_.message -match ".*Get-SiteListPassword.*" -or $_.message -match ".*Get-System.*" -or $_.message -match ".*Invoke-BypassUAC.*" -or $_.message -match ".*Invoke-Tater.*" -or $_.message -match ".*Invoke-WScriptBypassUAC.*" -or $_.message -match ".*PowerUp.*" -or $_.message -match ".*PowerView.*" -or $_.message -match ".*Get-RickAstley.*" -or $_.message -match ".*Find-Fruit.*" -or $_.message -match ".*HTTP-Login.*" -or $_.message -match ".*Find-TrustedDocuments.*" -or $_.message -match ".*Invoke-Paranoia.*" -or $_.message -match ".*Invoke-WinEnum.*" -or $_.message -match ".*Invoke-ARPScan.*" -or $_.message -match ".*Invoke-PortScan.*" -or $_.message -match ".*Invoke-ReverseDNSLookup.*" -or $_.message -match ".*Invoke-SMBScanner.*" -or $_.message -match ".*Invoke-Mimikittenz.*" -or $_.message -match ".*Invoke-AllChecks.*") -and  -not ($_.message -match "Get-SystemDriveInfo")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(Message.keyword:(*Invoke\-DllInjection* OR *Invoke\-Shellcode* OR *Invoke\-WmiCommand* OR *Get\-GPPPassword* OR *Get\-Keystrokes* OR *Get\-TimedScreenshot* OR *Get\-VaultCredential* OR *Invoke\-CredentialInjection* OR *Invoke\-Mimikatz* OR *Invoke\-NinjaCopy* OR *Invoke\-TokenManipulation* OR *Out\-Minidump* OR *VolumeShadowCopyTools* OR *Invoke\-ReflectivePEInjection* OR *Invoke\-UserHunter* OR *Find\-GPOLocation* OR *Invoke\-ACLScanner* OR *Invoke\-DowngradeAccount* OR *Get\-ServiceUnquoted* OR *Get\-ServiceFilePermission* OR *Get\-ServicePermission* OR *Invoke\-ServiceAbuse* OR *Install\-ServiceBinary* OR *Get\-RegAutoLogon* OR *Get\-VulnAutoRun* OR *Get\-VulnSchTask* OR *Get\-UnattendedInstallFile* OR *Get\-ApplicationHost* OR *Get\-RegAlwaysInstallElevated* OR *Get\-Unconstrained* OR *Add\-RegBackdoor* OR *Add\-ScrnSaveBackdoor* OR *Gupt\-Backdoor* OR *Invoke\-ADSBackdoor* OR *Enabled\-DuplicateToken* OR *Invoke\-PsUaCme* OR *Remove\-Update* OR *Check\-VM* OR *Get\-LSASecret* OR *Get\-PassHashes* OR *Show\-TargetScreen* OR *Port\-Scan* OR *Invoke\-PoshRatHttp* OR *Invoke\-PowerShellTCP* OR *Invoke\-PowerShellWMI* OR *Add\-Exfiltration* OR *Add\-Persistence* OR *Do\-Exfiltration* OR *Start\-CaptureServer* OR *Get\-ChromeDump* OR *Get\-ClipboardContents* OR *Get\-FoxDump* OR *Get\-IndexedItem* OR *Get\-Screenshot* OR *Invoke\-Inveigh* OR *Invoke\-NetRipper* OR *Invoke\-EgressCheck* OR *Invoke\-PostExfil* OR *Invoke\-PSInject* OR *Invoke\-RunAs* OR *MailRaider* OR *New\-HoneyHash* OR *Set\-MacAttribute* OR *Invoke\-DCSync* OR *Invoke\-PowerDump* OR *Exploit\-Jboss* OR *Invoke\-ThunderStruck* OR *Invoke\-VoiceTroll* OR *Set\-Wallpaper* OR *Invoke\-InveighRelay* OR *Invoke\-PsExec* OR *Invoke\-SSHCommand* OR *Get\-SecurityPackages* OR *Install\-SSP* OR *Invoke\-BackdoorLNK* OR *PowerBreach* OR *Get\-SiteListPassword* OR *Get\-System* OR *Invoke\-BypassUAC* OR *Invoke\-Tater* OR *Invoke\-WScriptBypassUAC* OR *PowerUp* OR *PowerView* OR *Get\-RickAstley* OR *Find\-Fruit* OR *HTTP\-Login* OR *Find\-TrustedDocuments* OR *Invoke\-Paranoia* OR *Invoke\-WinEnum* OR *Invoke\-ARPScan* OR *Invoke\-PortScan* OR *Invoke\-ReverseDNSLookup* OR *Invoke\-SMBScanner* OR *Invoke\-Mimikittenz* OR *Invoke\-AllChecks*) AND (NOT \*.keyword:(*Get\-SystemDriveInfo*)))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/89819aa4-bbd6-46bc-88ec-c7f7fe30efa6 <<EOF
{
  "metadata": {
    "title": "Malicious PowerShell Commandlets",
    "description": "Detects Commandlet names from well-known PowerShell exploitation frameworks",
    "tags": [
      "attack.execution",
      "attack.t1059.001",
      "attack.t1086"
    ],
    "query": "(Message.keyword:(*Invoke\\-DllInjection* OR *Invoke\\-Shellcode* OR *Invoke\\-WmiCommand* OR *Get\\-GPPPassword* OR *Get\\-Keystrokes* OR *Get\\-TimedScreenshot* OR *Get\\-VaultCredential* OR *Invoke\\-CredentialInjection* OR *Invoke\\-Mimikatz* OR *Invoke\\-NinjaCopy* OR *Invoke\\-TokenManipulation* OR *Out\\-Minidump* OR *VolumeShadowCopyTools* OR *Invoke\\-ReflectivePEInjection* OR *Invoke\\-UserHunter* OR *Find\\-GPOLocation* OR *Invoke\\-ACLScanner* OR *Invoke\\-DowngradeAccount* OR *Get\\-ServiceUnquoted* OR *Get\\-ServiceFilePermission* OR *Get\\-ServicePermission* OR *Invoke\\-ServiceAbuse* OR *Install\\-ServiceBinary* OR *Get\\-RegAutoLogon* OR *Get\\-VulnAutoRun* OR *Get\\-VulnSchTask* OR *Get\\-UnattendedInstallFile* OR *Get\\-ApplicationHost* OR *Get\\-RegAlwaysInstallElevated* OR *Get\\-Unconstrained* OR *Add\\-RegBackdoor* OR *Add\\-ScrnSaveBackdoor* OR *Gupt\\-Backdoor* OR *Invoke\\-ADSBackdoor* OR *Enabled\\-DuplicateToken* OR *Invoke\\-PsUaCme* OR *Remove\\-Update* OR *Check\\-VM* OR *Get\\-LSASecret* OR *Get\\-PassHashes* OR *Show\\-TargetScreen* OR *Port\\-Scan* OR *Invoke\\-PoshRatHttp* OR *Invoke\\-PowerShellTCP* OR *Invoke\\-PowerShellWMI* OR *Add\\-Exfiltration* OR *Add\\-Persistence* OR *Do\\-Exfiltration* OR *Start\\-CaptureServer* OR *Get\\-ChromeDump* OR *Get\\-ClipboardContents* OR *Get\\-FoxDump* OR *Get\\-IndexedItem* OR *Get\\-Screenshot* OR *Invoke\\-Inveigh* OR *Invoke\\-NetRipper* OR *Invoke\\-EgressCheck* OR *Invoke\\-PostExfil* OR *Invoke\\-PSInject* OR *Invoke\\-RunAs* OR *MailRaider* OR *New\\-HoneyHash* OR *Set\\-MacAttribute* OR *Invoke\\-DCSync* OR *Invoke\\-PowerDump* OR *Exploit\\-Jboss* OR *Invoke\\-ThunderStruck* OR *Invoke\\-VoiceTroll* OR *Set\\-Wallpaper* OR *Invoke\\-InveighRelay* OR *Invoke\\-PsExec* OR *Invoke\\-SSHCommand* OR *Get\\-SecurityPackages* OR *Install\\-SSP* OR *Invoke\\-BackdoorLNK* OR *PowerBreach* OR *Get\\-SiteListPassword* OR *Get\\-System* OR *Invoke\\-BypassUAC* OR *Invoke\\-Tater* OR *Invoke\\-WScriptBypassUAC* OR *PowerUp* OR *PowerView* OR *Get\\-RickAstley* OR *Find\\-Fruit* OR *HTTP\\-Login* OR *Find\\-TrustedDocuments* OR *Invoke\\-Paranoia* OR *Invoke\\-WinEnum* OR *Invoke\\-ARPScan* OR *Invoke\\-PortScan* OR *Invoke\\-ReverseDNSLookup* OR *Invoke\\-SMBScanner* OR *Invoke\\-Mimikittenz* OR *Invoke\\-AllChecks*) AND (NOT \\*.keyword:(*Get\\-SystemDriveInfo*)))"
  },
  "trigger": {
    "schedule": {
      "interval": "30m"
    }
  },
  "input": {
    "search": {
      "request": {
        "body": {
          "size": 0,
          "query": {
            "bool": {
              "must": [
                {
                  "query_string": {
                    "query": "(Message.keyword:(*Invoke\\-DllInjection* OR *Invoke\\-Shellcode* OR *Invoke\\-WmiCommand* OR *Get\\-GPPPassword* OR *Get\\-Keystrokes* OR *Get\\-TimedScreenshot* OR *Get\\-VaultCredential* OR *Invoke\\-CredentialInjection* OR *Invoke\\-Mimikatz* OR *Invoke\\-NinjaCopy* OR *Invoke\\-TokenManipulation* OR *Out\\-Minidump* OR *VolumeShadowCopyTools* OR *Invoke\\-ReflectivePEInjection* OR *Invoke\\-UserHunter* OR *Find\\-GPOLocation* OR *Invoke\\-ACLScanner* OR *Invoke\\-DowngradeAccount* OR *Get\\-ServiceUnquoted* OR *Get\\-ServiceFilePermission* OR *Get\\-ServicePermission* OR *Invoke\\-ServiceAbuse* OR *Install\\-ServiceBinary* OR *Get\\-RegAutoLogon* OR *Get\\-VulnAutoRun* OR *Get\\-VulnSchTask* OR *Get\\-UnattendedInstallFile* OR *Get\\-ApplicationHost* OR *Get\\-RegAlwaysInstallElevated* OR *Get\\-Unconstrained* OR *Add\\-RegBackdoor* OR *Add\\-ScrnSaveBackdoor* OR *Gupt\\-Backdoor* OR *Invoke\\-ADSBackdoor* OR *Enabled\\-DuplicateToken* OR *Invoke\\-PsUaCme* OR *Remove\\-Update* OR *Check\\-VM* OR *Get\\-LSASecret* OR *Get\\-PassHashes* OR *Show\\-TargetScreen* OR *Port\\-Scan* OR *Invoke\\-PoshRatHttp* OR *Invoke\\-PowerShellTCP* OR *Invoke\\-PowerShellWMI* OR *Add\\-Exfiltration* OR *Add\\-Persistence* OR *Do\\-Exfiltration* OR *Start\\-CaptureServer* OR *Get\\-ChromeDump* OR *Get\\-ClipboardContents* OR *Get\\-FoxDump* OR *Get\\-IndexedItem* OR *Get\\-Screenshot* OR *Invoke\\-Inveigh* OR *Invoke\\-NetRipper* OR *Invoke\\-EgressCheck* OR *Invoke\\-PostExfil* OR *Invoke\\-PSInject* OR *Invoke\\-RunAs* OR *MailRaider* OR *New\\-HoneyHash* OR *Set\\-MacAttribute* OR *Invoke\\-DCSync* OR *Invoke\\-PowerDump* OR *Exploit\\-Jboss* OR *Invoke\\-ThunderStruck* OR *Invoke\\-VoiceTroll* OR *Set\\-Wallpaper* OR *Invoke\\-InveighRelay* OR *Invoke\\-PsExec* OR *Invoke\\-SSHCommand* OR *Get\\-SecurityPackages* OR *Install\\-SSP* OR *Invoke\\-BackdoorLNK* OR *PowerBreach* OR *Get\\-SiteListPassword* OR *Get\\-System* OR *Invoke\\-BypassUAC* OR *Invoke\\-Tater* OR *Invoke\\-WScriptBypassUAC* OR *PowerUp* OR *PowerView* OR *Get\\-RickAstley* OR *Find\\-Fruit* OR *HTTP\\-Login* OR *Find\\-TrustedDocuments* OR *Invoke\\-Paranoia* OR *Invoke\\-WinEnum* OR *Invoke\\-ARPScan* OR *Invoke\\-PortScan* OR *Invoke\\-ReverseDNSLookup* OR *Invoke\\-SMBScanner* OR *Invoke\\-Mimikittenz* OR *Invoke\\-AllChecks*) AND (NOT \\*.keyword:(*Get\\-SystemDriveInfo*)))",
                    "analyze_wildcard": true
                  }
                }
              ],
              "filter": {
                "range": {
                  "timestamp": {
                    "gte": "now-30m/m"
                  }
                }
              }
            }
          }
        },
        "indices": [
          "winlogbeat-*"
        ]
      }
    }
  },
  "condition": {
    "compare": {
      "ctx.payload.hits.total": {
        "not_eq": 0
      }
    }
  },
  "actions": {
    "send_email": {
      "throttle_period": "15m",
      "email": {
        "profile": "standard",
        "from": "root@localhost",
        "to": "root@localhost",
        "subject": "Sigma Rule 'Malicious PowerShell Commandlets'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}{{_source}}\n================================================================================\n{{/ctx.payload.hits.hits}}",
        "attachments": {
          "data.json": {
            "data": {
              "format": "json"
            }
          }
        }
      }
    }
  }
}
EOF

```


### graylog
    
```
(Message.keyword:(*Invoke\-DllInjection* *Invoke\-Shellcode* *Invoke\-WmiCommand* *Get\-GPPPassword* *Get\-Keystrokes* *Get\-TimedScreenshot* *Get\-VaultCredential* *Invoke\-CredentialInjection* *Invoke\-Mimikatz* *Invoke\-NinjaCopy* *Invoke\-TokenManipulation* *Out\-Minidump* *VolumeShadowCopyTools* *Invoke\-ReflectivePEInjection* *Invoke\-UserHunter* *Find\-GPOLocation* *Invoke\-ACLScanner* *Invoke\-DowngradeAccount* *Get\-ServiceUnquoted* *Get\-ServiceFilePermission* *Get\-ServicePermission* *Invoke\-ServiceAbuse* *Install\-ServiceBinary* *Get\-RegAutoLogon* *Get\-VulnAutoRun* *Get\-VulnSchTask* *Get\-UnattendedInstallFile* *Get\-ApplicationHost* *Get\-RegAlwaysInstallElevated* *Get\-Unconstrained* *Add\-RegBackdoor* *Add\-ScrnSaveBackdoor* *Gupt\-Backdoor* *Invoke\-ADSBackdoor* *Enabled\-DuplicateToken* *Invoke\-PsUaCme* *Remove\-Update* *Check\-VM* *Get\-LSASecret* *Get\-PassHashes* *Show\-TargetScreen* *Port\-Scan* *Invoke\-PoshRatHttp* *Invoke\-PowerShellTCP* *Invoke\-PowerShellWMI* *Add\-Exfiltration* *Add\-Persistence* *Do\-Exfiltration* *Start\-CaptureServer* *Get\-ChromeDump* *Get\-ClipboardContents* *Get\-FoxDump* *Get\-IndexedItem* *Get\-Screenshot* *Invoke\-Inveigh* *Invoke\-NetRipper* *Invoke\-EgressCheck* *Invoke\-PostExfil* *Invoke\-PSInject* *Invoke\-RunAs* *MailRaider* *New\-HoneyHash* *Set\-MacAttribute* *Invoke\-DCSync* *Invoke\-PowerDump* *Exploit\-Jboss* *Invoke\-ThunderStruck* *Invoke\-VoiceTroll* *Set\-Wallpaper* *Invoke\-InveighRelay* *Invoke\-PsExec* *Invoke\-SSHCommand* *Get\-SecurityPackages* *Install\-SSP* *Invoke\-BackdoorLNK* *PowerBreach* *Get\-SiteListPassword* *Get\-System* *Invoke\-BypassUAC* *Invoke\-Tater* *Invoke\-WScriptBypassUAC* *PowerUp* *PowerView* *Get\-RickAstley* *Find\-Fruit* *HTTP\-Login* *Find\-TrustedDocuments* *Invoke\-Paranoia* *Invoke\-WinEnum* *Invoke\-ARPScan* *Invoke\-PortScan* *Invoke\-ReverseDNSLookup* *Invoke\-SMBScanner* *Invoke\-Mimikittenz* *Invoke\-AllChecks*) AND (NOT \*.keyword:(*Get\-SystemDriveInfo*)))
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-PowerShell/Operational" (Message="*Invoke-DllInjection*" OR Message="*Invoke-Shellcode*" OR Message="*Invoke-WmiCommand*" OR Message="*Get-GPPPassword*" OR Message="*Get-Keystrokes*" OR Message="*Get-TimedScreenshot*" OR Message="*Get-VaultCredential*" OR Message="*Invoke-CredentialInjection*" OR Message="*Invoke-Mimikatz*" OR Message="*Invoke-NinjaCopy*" OR Message="*Invoke-TokenManipulation*" OR Message="*Out-Minidump*" OR Message="*VolumeShadowCopyTools*" OR Message="*Invoke-ReflectivePEInjection*" OR Message="*Invoke-UserHunter*" OR Message="*Find-GPOLocation*" OR Message="*Invoke-ACLScanner*" OR Message="*Invoke-DowngradeAccount*" OR Message="*Get-ServiceUnquoted*" OR Message="*Get-ServiceFilePermission*" OR Message="*Get-ServicePermission*" OR Message="*Invoke-ServiceAbuse*" OR Message="*Install-ServiceBinary*" OR Message="*Get-RegAutoLogon*" OR Message="*Get-VulnAutoRun*" OR Message="*Get-VulnSchTask*" OR Message="*Get-UnattendedInstallFile*" OR Message="*Get-ApplicationHost*" OR Message="*Get-RegAlwaysInstallElevated*" OR Message="*Get-Unconstrained*" OR Message="*Add-RegBackdoor*" OR Message="*Add-ScrnSaveBackdoor*" OR Message="*Gupt-Backdoor*" OR Message="*Invoke-ADSBackdoor*" OR Message="*Enabled-DuplicateToken*" OR Message="*Invoke-PsUaCme*" OR Message="*Remove-Update*" OR Message="*Check-VM*" OR Message="*Get-LSASecret*" OR Message="*Get-PassHashes*" OR Message="*Show-TargetScreen*" OR Message="*Port-Scan*" OR Message="*Invoke-PoshRatHttp*" OR Message="*Invoke-PowerShellTCP*" OR Message="*Invoke-PowerShellWMI*" OR Message="*Add-Exfiltration*" OR Message="*Add-Persistence*" OR Message="*Do-Exfiltration*" OR Message="*Start-CaptureServer*" OR Message="*Get-ChromeDump*" OR Message="*Get-ClipboardContents*" OR Message="*Get-FoxDump*" OR Message="*Get-IndexedItem*" OR Message="*Get-Screenshot*" OR Message="*Invoke-Inveigh*" OR Message="*Invoke-NetRipper*" OR Message="*Invoke-EgressCheck*" OR Message="*Invoke-PostExfil*" OR Message="*Invoke-PSInject*" OR Message="*Invoke-RunAs*" OR Message="*MailRaider*" OR Message="*New-HoneyHash*" OR Message="*Set-MacAttribute*" OR Message="*Invoke-DCSync*" OR Message="*Invoke-PowerDump*" OR Message="*Exploit-Jboss*" OR Message="*Invoke-ThunderStruck*" OR Message="*Invoke-VoiceTroll*" OR Message="*Set-Wallpaper*" OR Message="*Invoke-InveighRelay*" OR Message="*Invoke-PsExec*" OR Message="*Invoke-SSHCommand*" OR Message="*Get-SecurityPackages*" OR Message="*Install-SSP*" OR Message="*Invoke-BackdoorLNK*" OR Message="*PowerBreach*" OR Message="*Get-SiteListPassword*" OR Message="*Get-System*" OR Message="*Invoke-BypassUAC*" OR Message="*Invoke-Tater*" OR Message="*Invoke-WScriptBypassUAC*" OR Message="*PowerUp*" OR Message="*PowerView*" OR Message="*Get-RickAstley*" OR Message="*Find-Fruit*" OR Message="*HTTP-Login*" OR Message="*Find-TrustedDocuments*" OR Message="*Invoke-Paranoia*" OR Message="*Invoke-WinEnum*" OR Message="*Invoke-ARPScan*" OR Message="*Invoke-PortScan*" OR Message="*Invoke-ReverseDNSLookup*" OR Message="*Invoke-SMBScanner*" OR Message="*Invoke-Mimikittenz*" OR Message="*Invoke-AllChecks*") NOT ("Get-SystemDriveInfo"))
```


### logpoint
    
```
(Message IN ["*Invoke-DllInjection*", "*Invoke-Shellcode*", "*Invoke-WmiCommand*", "*Get-GPPPassword*", "*Get-Keystrokes*", "*Get-TimedScreenshot*", "*Get-VaultCredential*", "*Invoke-CredentialInjection*", "*Invoke-Mimikatz*", "*Invoke-NinjaCopy*", "*Invoke-TokenManipulation*", "*Out-Minidump*", "*VolumeShadowCopyTools*", "*Invoke-ReflectivePEInjection*", "*Invoke-UserHunter*", "*Find-GPOLocation*", "*Invoke-ACLScanner*", "*Invoke-DowngradeAccount*", "*Get-ServiceUnquoted*", "*Get-ServiceFilePermission*", "*Get-ServicePermission*", "*Invoke-ServiceAbuse*", "*Install-ServiceBinary*", "*Get-RegAutoLogon*", "*Get-VulnAutoRun*", "*Get-VulnSchTask*", "*Get-UnattendedInstallFile*", "*Get-ApplicationHost*", "*Get-RegAlwaysInstallElevated*", "*Get-Unconstrained*", "*Add-RegBackdoor*", "*Add-ScrnSaveBackdoor*", "*Gupt-Backdoor*", "*Invoke-ADSBackdoor*", "*Enabled-DuplicateToken*", "*Invoke-PsUaCme*", "*Remove-Update*", "*Check-VM*", "*Get-LSASecret*", "*Get-PassHashes*", "*Show-TargetScreen*", "*Port-Scan*", "*Invoke-PoshRatHttp*", "*Invoke-PowerShellTCP*", "*Invoke-PowerShellWMI*", "*Add-Exfiltration*", "*Add-Persistence*", "*Do-Exfiltration*", "*Start-CaptureServer*", "*Get-ChromeDump*", "*Get-ClipboardContents*", "*Get-FoxDump*", "*Get-IndexedItem*", "*Get-Screenshot*", "*Invoke-Inveigh*", "*Invoke-NetRipper*", "*Invoke-EgressCheck*", "*Invoke-PostExfil*", "*Invoke-PSInject*", "*Invoke-RunAs*", "*MailRaider*", "*New-HoneyHash*", "*Set-MacAttribute*", "*Invoke-DCSync*", "*Invoke-PowerDump*", "*Exploit-Jboss*", "*Invoke-ThunderStruck*", "*Invoke-VoiceTroll*", "*Set-Wallpaper*", "*Invoke-InveighRelay*", "*Invoke-PsExec*", "*Invoke-SSHCommand*", "*Get-SecurityPackages*", "*Install-SSP*", "*Invoke-BackdoorLNK*", "*PowerBreach*", "*Get-SiteListPassword*", "*Get-System*", "*Invoke-BypassUAC*", "*Invoke-Tater*", "*Invoke-WScriptBypassUAC*", "*PowerUp*", "*PowerView*", "*Get-RickAstley*", "*Find-Fruit*", "*HTTP-Login*", "*Find-TrustedDocuments*", "*Invoke-Paranoia*", "*Invoke-WinEnum*", "*Invoke-ARPScan*", "*Invoke-PortScan*", "*Invoke-ReverseDNSLookup*", "*Invoke-SMBScanner*", "*Invoke-Mimikittenz*", "*Invoke-AllChecks*"]  -("Get-SystemDriveInfo"))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*Invoke-DllInjection.*|.*.*Invoke-Shellcode.*|.*.*Invoke-WmiCommand.*|.*.*Get-GPPPassword.*|.*.*Get-Keystrokes.*|.*.*Get-TimedScreenshot.*|.*.*Get-VaultCredential.*|.*.*Invoke-CredentialInjection.*|.*.*Invoke-Mimikatz.*|.*.*Invoke-NinjaCopy.*|.*.*Invoke-TokenManipulation.*|.*.*Out-Minidump.*|.*.*VolumeShadowCopyTools.*|.*.*Invoke-ReflectivePEInjection.*|.*.*Invoke-UserHunter.*|.*.*Find-GPOLocation.*|.*.*Invoke-ACLScanner.*|.*.*Invoke-DowngradeAccount.*|.*.*Get-ServiceUnquoted.*|.*.*Get-ServiceFilePermission.*|.*.*Get-ServicePermission.*|.*.*Invoke-ServiceAbuse.*|.*.*Install-ServiceBinary.*|.*.*Get-RegAutoLogon.*|.*.*Get-VulnAutoRun.*|.*.*Get-VulnSchTask.*|.*.*Get-UnattendedInstallFile.*|.*.*Get-ApplicationHost.*|.*.*Get-RegAlwaysInstallElevated.*|.*.*Get-Unconstrained.*|.*.*Add-RegBackdoor.*|.*.*Add-ScrnSaveBackdoor.*|.*.*Gupt-Backdoor.*|.*.*Invoke-ADSBackdoor.*|.*.*Enabled-DuplicateToken.*|.*.*Invoke-PsUaCme.*|.*.*Remove-Update.*|.*.*Check-VM.*|.*.*Get-LSASecret.*|.*.*Get-PassHashes.*|.*.*Show-TargetScreen.*|.*.*Port-Scan.*|.*.*Invoke-PoshRatHttp.*|.*.*Invoke-PowerShellTCP.*|.*.*Invoke-PowerShellWMI.*|.*.*Add-Exfiltration.*|.*.*Add-Persistence.*|.*.*Do-Exfiltration.*|.*.*Start-CaptureServer.*|.*.*Get-ChromeDump.*|.*.*Get-ClipboardContents.*|.*.*Get-FoxDump.*|.*.*Get-IndexedItem.*|.*.*Get-Screenshot.*|.*.*Invoke-Inveigh.*|.*.*Invoke-NetRipper.*|.*.*Invoke-EgressCheck.*|.*.*Invoke-PostExfil.*|.*.*Invoke-PSInject.*|.*.*Invoke-RunAs.*|.*.*MailRaider.*|.*.*New-HoneyHash.*|.*.*Set-MacAttribute.*|.*.*Invoke-DCSync.*|.*.*Invoke-PowerDump.*|.*.*Exploit-Jboss.*|.*.*Invoke-ThunderStruck.*|.*.*Invoke-VoiceTroll.*|.*.*Set-Wallpaper.*|.*.*Invoke-InveighRelay.*|.*.*Invoke-PsExec.*|.*.*Invoke-SSHCommand.*|.*.*Get-SecurityPackages.*|.*.*Install-SSP.*|.*.*Invoke-BackdoorLNK.*|.*.*PowerBreach.*|.*.*Get-SiteListPassword.*|.*.*Get-System.*|.*.*Invoke-BypassUAC.*|.*.*Invoke-Tater.*|.*.*Invoke-WScriptBypassUAC.*|.*.*PowerUp.*|.*.*PowerView.*|.*.*Get-RickAstley.*|.*.*Find-Fruit.*|.*.*HTTP-Login.*|.*.*Find-TrustedDocuments.*|.*.*Invoke-Paranoia.*|.*.*Invoke-WinEnum.*|.*.*Invoke-ARPScan.*|.*.*Invoke-PortScan.*|.*.*Invoke-ReverseDNSLookup.*|.*.*Invoke-SMBScanner.*|.*.*Invoke-Mimikittenz.*|.*.*Invoke-AllChecks.*))(?=.*(?!.*(?:.*(?:.*Get-SystemDriveInfo)))))'
```



