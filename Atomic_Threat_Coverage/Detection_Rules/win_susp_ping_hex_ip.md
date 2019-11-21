| Title                | Ping Hex IP                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a ping command that uses a hex encoded IP address                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1140: Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140)</li><li>[T1027: Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1140: Deobfuscate/Decode Files or Information](../Triggers/T1140.md)</li><li>[T1027: Obfuscated Files or Information](../Triggers/T1027.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Unlikely, because no sane admin pings IP addresses in a hexadecimal form</li></ul>  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           | <ul><li>[https://github.com/vysec/Aggressor-VYSEC/blob/master/ping.cna](https://github.com/vysec/Aggressor-VYSEC/blob/master/ping.cna)</li><li>[https://twitter.com/vysecurity/status/977198418354491392](https://twitter.com/vysecurity/status/977198418354491392)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Ping Hex IP
id: 1a0d4aba-7668-4365-9ce4-6d79ab088dfd
description: Detects a ping command that uses a hex encoded IP address
references:
    - https://github.com/vysec/Aggressor-VYSEC/blob/master/ping.cna
    - https://twitter.com/vysecurity/status/977198418354491392
author: Florian Roth
date: 2018/03/23
tags:
    - attack.defense_evasion
    - attack.t1140
    - attack.t1027
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - '*\ping.exe 0x*'
            - '*\ping 0x*'
    condition: selection
fields:
    - ParentCommandLine
falsepositives:
    - Unlikely, because no sane admin pings IP addresses in a hexadecimal form
level: high

```





### splunk
    
```
(CommandLine="*\\\\ping.exe 0x*" OR CommandLine="*\\\\ping 0x*") | table ParentCommandLine
```



