| Title                | Winlogon Helper DLL                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Winlogon.exe is a Windows component responsible for actions at logon/logoff as well as the secure attention sequence (SAS) triggered by Ctrl-Alt-Delete. Registry entries in HKLM\Software[Wow6432Node]Microsoft\Windows NT\CurrentVersion\Winlogon\ and HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ are used to manage additional helper programs and functionalities that support Winlogon. Malicious modifications to these Registry keys may cause Winlogon to load and execute malicious DLLs and/or executables.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1004: Winlogon Helper DLL](https://attack.mitre.org/techniques/T1004)</li></ul>  |
| Data Needed          | <ul><li>[DN_0036_4104_windows_powershell_script_block](../Data_Needed/DN_0036_4104_windows_powershell_script_block.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1004: Winlogon Helper DLL](../Triggers/T1004.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1004/T1004.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1004/T1004.yaml)</li></ul>  |
| Author               | Timur Zinniatullin, oscd.community |


## Detection Rules

### Sigma rule

```
title: Winlogon Helper DLL
id: 851c506b-6b7c-4ce2-8802-c703009d03c0
status: experimental
description: Winlogon.exe is a Windows component responsible for actions at logon/logoff as well as the secure attention sequence (SAS) triggered by Ctrl-Alt-Delete.
    Registry entries in HKLM\Software[Wow6432Node]Microsoft\Windows NT\CurrentVersion\Winlogon\ and HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ are
    used to manage additional helper programs and functionalities that support Winlogon. Malicious modifications to these Registry keys may cause Winlogon to load
    and execute malicious DLLs and/or executables.
author: Timur Zinniatullin, oscd.community
date: 2019/10/21
modified: 2019/11/04
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1004/T1004.yaml
logsource:
    product: windows
    service: powershell
    description: 'Script block logging must be enabled'
detection:
    selection:
        EventID: 4104
    keyword1: 
        - '*Set-ItemProperty*'
        - '*New-Item*'
    keyword2: 
        - '*CurrentVersion\Winlogon*'
    condition: selection and ( keyword1 and keyword2 )
falsepositives:
    - Unknown
level: medium
tags:
    - attack.persistence
    - attack.t1004

```





### splunk
    
```
(EventID="4104" ("*Set-ItemProperty*" OR "*New-Item*") "*CurrentVersion\\\\Winlogon*")
```



