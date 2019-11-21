| Title                | MMC Spawning Windows Shell                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a Windows command line executable started from MMC.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1175: Component Object Model and Distributed COM](https://attack.mitre.org/techniques/T1175)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1175: Component Object Model and Distributed COM](../Triggers/T1175.md)</li></ul>  |
| Severity Level       | high |
| False Positives      |  There are no documented False Positives for this Detection Rule yet  |
| Development Status   | experimental |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Karneades, Swisscom CSIRT |


## Detection Rules

### Sigma rule

```
title: MMC Spawning Windows Shell
id: 05a2ab7e-ce11-4b63-86db-ab32e763e11d
status: experimental
description: Detects a Windows command line executable started from MMC.
author: Karneades, Swisscom CSIRT
tags:
    - attack.lateral_movement
    - attack.t1175
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage: '*\mmc.exe'
        Image:
            - '*\cmd.exe'
            - '*\powershell.exe'
            - '*\wscript.exe'
            - '*\cscript.exe'
            - '*\sh.exe'
            - '*\bash.exe'
            - '*\reg.exe'
            - '*\regsvr32.exe'
            - '*\BITSADMIN*'
    condition: selection
fields:
    - CommandLine
    - Image
    - ParentCommandLine
level: high

```





### splunk
    
```
(ParentImage="*\\\\mmc.exe" (Image="*\\\\cmd.exe" OR Image="*\\\\powershell.exe" OR Image="*\\\\wscript.exe" OR Image="*\\\\cscript.exe" OR Image="*\\\\sh.exe" OR Image="*\\\\bash.exe" OR Image="*\\\\reg.exe" OR Image="*\\\\regsvr32.exe" OR Image="*\\\\BITSADMIN*")) | table CommandLine,Image,ParentCommandLine
```



