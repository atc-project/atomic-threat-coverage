| Title                | Malicious PowerShell Commandlets                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects Commandlet names from well-known PowerShell exploitation frameworks                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| Data Needed          |  There is no documented Data Needed for this Detection Rule yet  |
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
    false_positives:
        - Get-SystemDriveInfo  # http://bheltborg.dk/Windows/WinSxS/amd64_microsoft-windows-maintenancediagnostic_31bf3856ad364e35_10.0.10240.16384_none_91ef7543a4514b5e/CL_Utility.ps1
    condition: keywords and not false_positives
falsepositives:
    - Penetration testing
level: high

```





### splunk
    
```
((Message="*Invoke-DllInjection*" OR Message="*Invoke-Shellcode*" OR Message="*Invoke-WmiCommand*" OR Message="*Get-GPPPassword*" OR Message="*Get-Keystrokes*" OR Message="*Get-TimedScreenshot*" OR Message="*Get-VaultCredential*" OR Message="*Invoke-CredentialInjection*" OR Message="*Invoke-Mimikatz*" OR Message="*Invoke-NinjaCopy*" OR Message="*Invoke-TokenManipulation*" OR Message="*Out-Minidump*" OR Message="*VolumeShadowCopyTools*" OR Message="*Invoke-ReflectivePEInjection*" OR Message="*Invoke-UserHunter*" OR Message="*Find-GPOLocation*" OR Message="*Invoke-ACLScanner*" OR Message="*Invoke-DowngradeAccount*" OR Message="*Get-ServiceUnquoted*" OR Message="*Get-ServiceFilePermission*" OR Message="*Get-ServicePermission*" OR Message="*Invoke-ServiceAbuse*" OR Message="*Install-ServiceBinary*" OR Message="*Get-RegAutoLogon*" OR Message="*Get-VulnAutoRun*" OR Message="*Get-VulnSchTask*" OR Message="*Get-UnattendedInstallFile*" OR Message="*Get-ApplicationHost*" OR Message="*Get-RegAlwaysInstallElevated*" OR Message="*Get-Unconstrained*" OR Message="*Add-RegBackdoor*" OR Message="*Add-ScrnSaveBackdoor*" OR Message="*Gupt-Backdoor*" OR Message="*Invoke-ADSBackdoor*" OR Message="*Enabled-DuplicateToken*" OR Message="*Invoke-PsUaCme*" OR Message="*Remove-Update*" OR Message="*Check-VM*" OR Message="*Get-LSASecret*" OR Message="*Get-PassHashes*" OR Message="*Show-TargetScreen*" OR Message="*Port-Scan*" OR Message="*Invoke-PoshRatHttp*" OR Message="*Invoke-PowerShellTCP*" OR Message="*Invoke-PowerShellWMI*" OR Message="*Add-Exfiltration*" OR Message="*Add-Persistence*" OR Message="*Do-Exfiltration*" OR Message="*Start-CaptureServer*" OR Message="*Get-ChromeDump*" OR Message="*Get-ClipboardContents*" OR Message="*Get-FoxDump*" OR Message="*Get-IndexedItem*" OR Message="*Get-Screenshot*" OR Message="*Invoke-Inveigh*" OR Message="*Invoke-NetRipper*" OR Message="*Invoke-EgressCheck*" OR Message="*Invoke-PostExfil*" OR Message="*Invoke-PSInject*" OR Message="*Invoke-RunAs*" OR Message="*MailRaider*" OR Message="*New-HoneyHash*" OR Message="*Set-MacAttribute*" OR Message="*Invoke-DCSync*" OR Message="*Invoke-PowerDump*" OR Message="*Exploit-Jboss*" OR Message="*Invoke-ThunderStruck*" OR Message="*Invoke-VoiceTroll*" OR Message="*Set-Wallpaper*" OR Message="*Invoke-InveighRelay*" OR Message="*Invoke-PsExec*" OR Message="*Invoke-SSHCommand*" OR Message="*Get-SecurityPackages*" OR Message="*Install-SSP*" OR Message="*Invoke-BackdoorLNK*" OR Message="*PowerBreach*" OR Message="*Get-SiteListPassword*" OR Message="*Get-System*" OR Message="*Invoke-BypassUAC*" OR Message="*Invoke-Tater*" OR Message="*Invoke-WScriptBypassUAC*" OR Message="*PowerUp*" OR Message="*PowerView*" OR Message="*Get-RickAstley*" OR Message="*Find-Fruit*" OR Message="*HTTP-Login*" OR Message="*Find-TrustedDocuments*" OR Message="*Invoke-Paranoia*" OR Message="*Invoke-WinEnum*" OR Message="*Invoke-ARPScan*" OR Message="*Invoke-PortScan*" OR Message="*Invoke-ReverseDNSLookup*" OR Message="*Invoke-SMBScanner*" OR Message="*Invoke-Mimikittenz*") NOT ("Get-SystemDriveInfo"))
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Malicious PowerShell Commandlets]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Malicious PowerShell Commandlets status: experimental \
description: Detects Commandlet names from well-known PowerShell exploitation frameworks \
references: ['https://adsecurity.org/?p=2921'] \
tags: ['attack.execution', 'attack.t1086'] \
author: Sean Metcalf (source), Florian Roth (rule) \
date:  \
falsepositives: ['Penetration testing'] \
level: high
action.email.useNSSubject = 1
alert.severity = 1
alert.suppress = 0
alert.track = 1
alert.expires = 24h
counttype = number of events
cron_schedule = */10 * * * *
allow_skew = 50%
schedule_window = auto
description = Detects Commandlet names from well-known PowerShell exploitation frameworks
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = ((Message="*Invoke-DllInjection*" OR Message="*Invoke-Shellcode*" OR Message="*Invoke-WmiCommand*" OR Message="*Get-GPPPassword*" OR Message="*Get-Keystrokes*" OR Message="*Get-TimedScreenshot*" OR Message="*Get-VaultCredential*" OR Message="*Invoke-CredentialInjection*" OR Message="*Invoke-Mimikatz*" OR Message="*Invoke-NinjaCopy*" OR Message="*Invoke-TokenManipulation*" OR Message="*Out-Minidump*" OR Message="*VolumeShadowCopyTools*" OR Message="*Invoke-ReflectivePEInjection*" OR Message="*Invoke-UserHunter*" OR Message="*Find-GPOLocation*" OR Message="*Invoke-ACLScanner*" OR Message="*Invoke-DowngradeAccount*" OR Message="*Get-ServiceUnquoted*" OR Message="*Get-ServiceFilePermission*" OR Message="*Get-ServicePermission*" OR Message="*Invoke-ServiceAbuse*" OR Message="*Install-ServiceBinary*" OR Message="*Get-RegAutoLogon*" OR Message="*Get-VulnAutoRun*" OR Message="*Get-VulnSchTask*" OR Message="*Get-UnattendedInstallFile*" OR Message="*Get-ApplicationHost*" OR Message="*Get-RegAlwaysInstallElevated*" OR Message="*Get-Unconstrained*" OR Message="*Add-RegBackdoor*" OR Message="*Add-ScrnSaveBackdoor*" OR Message="*Gupt-Backdoor*" OR Message="*Invoke-ADSBackdoor*" OR Message="*Enabled-DuplicateToken*" OR Message="*Invoke-PsUaCme*" OR Message="*Remove-Update*" OR Message="*Check-VM*" OR Message="*Get-LSASecret*" OR Message="*Get-PassHashes*" OR Message="*Show-TargetScreen*" OR Message="*Port-Scan*" OR Message="*Invoke-PoshRatHttp*" OR Message="*Invoke-PowerShellTCP*" OR Message="*Invoke-PowerShellWMI*" OR Message="*Add-Exfiltration*" OR Message="*Add-Persistence*" OR Message="*Do-Exfiltration*" OR Message="*Start-CaptureServer*" OR Message="*Get-ChromeDump*" OR Message="*Get-ClipboardContents*" OR Message="*Get-FoxDump*" OR Message="*Get-IndexedItem*" OR Message="*Get-Screenshot*" OR Message="*Invoke-Inveigh*" OR Message="*Invoke-NetRipper*" OR Message="*Invoke-EgressCheck*" OR Message="*Invoke-PostExfil*" OR Message="*Invoke-PSInject*" OR Message="*Invoke-RunAs*" OR Message="*MailRaider*" OR Message="*New-HoneyHash*" OR Message="*Set-MacAttribute*" OR Message="*Invoke-DCSync*" OR Message="*Invoke-PowerDump*" OR Message="*Exploit-Jboss*" OR Message="*Invoke-ThunderStruck*" OR Message="*Invoke-VoiceTroll*" OR Message="*Set-Wallpaper*" OR Message="*Invoke-InveighRelay*" OR Message="*Invoke-PsExec*" OR Message="*Invoke-SSHCommand*" OR Message="*Get-SecurityPackages*" OR Message="*Install-SSP*" OR Message="*Invoke-BackdoorLNK*" OR Message="*PowerBreach*" OR Message="*Get-SiteListPassword*" OR Message="*Get-System*" OR Message="*Invoke-BypassUAC*" OR Message="*Invoke-Tater*" OR Message="*Invoke-WScriptBypassUAC*" OR Message="*PowerUp*" OR Message="*PowerView*" OR Message="*Get-RickAstley*" OR Message="*Find-Fruit*" OR Message="*HTTP-Login*" OR Message="*Find-TrustedDocuments*" OR Message="*Invoke-Paranoia*" OR Message="*Invoke-WinEnum*" OR Message="*Invoke-ARPScan*" OR Message="*Invoke-PortScan*" OR Message="*Invoke-ReverseDNSLookup*" OR Message="*Invoke-SMBScanner*" OR Message="*Invoke-Mimikittenz*") NOT ("Get-SystemDriveInfo")) | stats values(*) AS * by _time | search NOT [| inputlookup Malicious_PowerShell_Commandlets_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.execution,sigma_tag=attack.t1086,level=high"
```
