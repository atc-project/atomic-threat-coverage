| Title                | Adwind RAT / JRAT                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects javaw.exe in AppData folder as used by Adwind / JRAT                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1064: Scripting](https://attack.mitre.org/techniques/T1064)</li></ul>  |
| Data Needed          | <ul><li>[DN_0015_11_windows_sysmon_FileCreate](../Data_Needed/DN_0015_11_windows_sysmon_FileCreate.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1064: Scripting](../Triggers/T1064.md)</li></ul>  |
| Severity Level       | high |
| False Positives      |  There are no documented False Positives for this Detection Rule yet  |
| Development Status   | experimental |
| References           | <ul><li>[https://www.hybrid-analysis.com/sample/ba86fa0d4b6af2db0656a88b1dd29f36fe362473ae8ad04255c4e52f214a541c?environmentId=100](https://www.hybrid-analysis.com/sample/ba86fa0d4b6af2db0656a88b1dd29f36fe362473ae8ad04255c4e52f214a541c?environmentId=100)</li><li>[https://www.first.org/resources/papers/conf2017/Advanced-Incident-Detection-and-Threat-Hunting-using-Sysmon-and-Splunk.pdf](https://www.first.org/resources/papers/conf2017/Advanced-Incident-Detection-and-Threat-Hunting-using-Sysmon-and-Splunk.pdf)</li></ul>  |
| Author               | Florian Roth, Tom Ueltschi |


## Detection Rules

### Sigma rule

```
action: global
title: Adwind RAT / JRAT
id: 1fac1481-2dbc-48b2-9096-753c49b4ec71
status: experimental
description: Detects javaw.exe in AppData folder as used by Adwind / JRAT
references:
    - https://www.hybrid-analysis.com/sample/ba86fa0d4b6af2db0656a88b1dd29f36fe362473ae8ad04255c4e52f214a541c?environmentId=100
    - https://www.first.org/resources/papers/conf2017/Advanced-Incident-Detection-and-Threat-Hunting-using-Sysmon-and-Splunk.pdf
author: Florian Roth, Tom Ueltschi
date: 2017/11/10
modified: 2018/12/11
tags:
    - attack.execution
    - attack.t1064
detection:
    condition: selection
level: high
---
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - '*\AppData\Roaming\Oracle*\java*.exe *'
            - '*cscript.exe *Retrive*.vbs *'
---
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 11
        TargetFilename:
            - '*\AppData\Roaming\Oracle\bin\java*.exe'
            - '*\Retrive*.vbs'
---
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 13
        TargetObject: \REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run*
        Details: '%AppData%\Roaming\Oracle\bin\\*'

```





### splunk
    
```
(CommandLine="*\\\\AppData\\\\Roaming\\\\Oracle*\\\\java*.exe *" OR CommandLine="*cscript.exe *Retrive*.vbs *")\n(EventID="11" (TargetFilename="*\\\\AppData\\\\Roaming\\\\Oracle\\\\bin\\\\java*.exe" OR TargetFilename="*\\\\Retrive*.vbs"))\n(EventID="13" TargetObject="\\\\REGISTRY\\\\MACHINE\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run*" Details="%AppData%\\\\Roaming\\\\Oracle\\\\bin\\\\*")
```



