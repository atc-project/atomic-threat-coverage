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






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Ping Hex IP]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:  \
ParentCommandLine: $result.ParentCommandLine$  \
title: Ping Hex IP status:  \
description: Detects a ping command that uses a hex encoded IP address \
references: ['https://github.com/vysec/Aggressor-VYSEC/blob/master/ping.cna', 'https://twitter.com/vysecurity/status/977198418354491392'] \
tags: ['attack.defense_evasion', 'attack.t1140', 'attack.t1027'] \
author: Florian Roth \
date:  \
falsepositives: ['Unlikely, because no sane admin pings IP addresses in a hexadecimal form'] \
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
description = Detects a ping command that uses a hex encoded IP address
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (CommandLine="*\\ping.exe 0x*" OR CommandLine="*\\ping 0x*") | table ParentCommandLine,host | search NOT [| inputlookup Ping_Hex_IP_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.defense_evasion,sigma_tag=attack.t1140,sigma_tag=attack.t1027,level=high"
```
