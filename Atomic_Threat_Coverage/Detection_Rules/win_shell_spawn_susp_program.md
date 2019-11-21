| Title                | Windows Shell Spawning Suspicious Program                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a suspicious child process of a Windows shell                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1064: Scripting](https://attack.mitre.org/techniques/T1064)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1064: Scripting](../Triggers/T1064.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Administrative scripts</li><li>Microsoft SCCM</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://mgreen27.github.io/posts/2018/04/02/DownloadCradle.html](https://mgreen27.github.io/posts/2018/04/02/DownloadCradle.html)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Windows Shell Spawning Suspicious Program
id: 3a6586ad-127a-4d3b-a677-1e6eacdf8fde
status: experimental
description: Detects a suspicious child process of a Windows shell
references:
    - https://mgreen27.github.io/posts/2018/04/02/DownloadCradle.html
author: Florian Roth
date: 2018/04/06
modified: 2019/02/05
tags:
    - attack.execution
    - attack.defense_evasion
    - attack.t1064
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage:
            - '*\mshta.exe'
            - '*\powershell.exe'
            # - '*\cmd.exe'  # too many false positives
            - '*\rundll32.exe'
            - '*\cscript.exe'
            - '*\wscript.exe'
            - '*\wmiprvse.exe'
        Image:
            - '*\schtasks.exe'
            - '*\nslookup.exe'
            - '*\certutil.exe'
            - '*\bitsadmin.exe'
            - '*\mshta.exe'
    falsepositives:
        CurrentDirectory: '*\ccmcache\\*'
    condition: selection and not falsepositives
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Administrative scripts
    - Microsoft SCCM
level: high

```





### splunk
    
```
(((ParentImage="*\\\\mshta.exe" OR ParentImage="*\\\\powershell.exe" OR ParentImage="*\\\\rundll32.exe" OR ParentImage="*\\\\cscript.exe" OR ParentImage="*\\\\wscript.exe" OR ParentImage="*\\\\wmiprvse.exe") (Image="*\\\\schtasks.exe" OR Image="*\\\\nslookup.exe" OR Image="*\\\\certutil.exe" OR Image="*\\\\bitsadmin.exe" OR Image="*\\\\mshta.exe")) NOT (CurrentDirectory="*\\\\ccmcache\\\\*")) | table CommandLine,ParentCommandLine
```



