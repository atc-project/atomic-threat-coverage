| Title                | Suspicious Use of Procdump                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious uses of the SysInternals Procdump utility by using a special command line parameter in combination with the lsass.exe process. This way we're also able to catch cases in which the attacker has renamed the procdump executable.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1036: Masquerading](https://attack.mitre.org/techniques/T1036)</li><li>[T1003: Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1036: Masquerading](../Triggers/T1036.md)</li><li>[T1003: Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Unlikely, because no one should dump an lsass process memory</li><li>Another tool that uses the command line switches of Procdump</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[Internal Research](Internal Research)</li></ul>  |
| Author               | Florian Roth |
| Other Tags           | <ul><li>car.2013-05-009</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Suspicious Use of Procdump
id: 5afee48e-67dd-4e03-a783-f74259dcf998
description: Detects suspicious uses of the SysInternals Procdump utility by using a special command line parameter in combination with the lsass.exe process. This way we're also able to catch cases in which the attacker has renamed the procdump executable.
status: experimental
references:
    - Internal Research
author: Florian Roth
date: 2018/10/30
modified: 2019/10/14
tags:
    - attack.defense_evasion
    - attack.t1036
    - attack.credential_access
    - attack.t1003
    - car.2013-05-009
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine:
            - '* -ma *'
    selection2:
        CommandLine:
            - '* lsass*'
    selection3:
        CommandLine:
            - '* -ma ls*'
    condition: ( selection1 and selection2 ) or selection3
falsepositives:
    - Unlikely, because no one should dump an lsass process memory
    - Another tool that uses the command line switches of Procdump
level: medium

```





### splunk
    
```
(((CommandLine="* -ma *") (CommandLine="* lsass*")) OR (CommandLine="* -ma ls*"))
```



