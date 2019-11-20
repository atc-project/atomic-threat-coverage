| Title                | Netsh                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Allow Incoming Connections by Port or Application on Windows Firewall                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li><li>[TA0011: Command and Control](https://attack.mitre.org/tactics/TA0011)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1090: Connection Proxy](https://attack.mitre.org/techniques/T1090)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1090: Connection Proxy](../Triggers/T1090.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Legitimate administration</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://attack.mitre.org/software/S0246/ (Lazarus HARDRAIN)](https://attack.mitre.org/software/S0246/ (Lazarus HARDRAIN))</li><li>[https://www.operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-RAT-and-Staging-Report.pdf](https://www.operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-RAT-and-Staging-Report.pdf)</li></ul>  |
| Author               | Markus Neis |


## Detection Rules

### Sigma rule

```
title: Netsh
id: cd5cfd80-aa5f-44c0-9c20-108c4ae12e3c
description: Allow Incoming Connections by Port or Application on Windows Firewall
references:
    - https://attack.mitre.org/software/S0246/ (Lazarus HARDRAIN)
    - https://www.operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-RAT-and-Staging-Report.pdf
date: 2019/01/29
tags:
    - attack.lateral_movement
    - attack.command_and_control
    - attack.t1090 
status: experimental
author: Markus Neis
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - '*netsh firewall add*'
    condition: selection
falsepositives:
    - Legitimate administration
level: medium

```





### splunk
    
```
(CommandLine="*netsh firewall add*")
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Netsh]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Netsh status: experimental \
description: Allow Incoming Connections by Port or Application on Windows Firewall \
references: ['https://attack.mitre.org/software/S0246/ (Lazarus HARDRAIN)', 'https://www.operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-RAT-and-Staging-Report.pdf'] \
tags: ['attack.lateral_movement', 'attack.command_and_control', 'attack.t1090'] \
author: Markus Neis \
date:  \
falsepositives: ['Legitimate administration'] \
level: medium
action.email.useNSSubject = 1
alert.severity = 1
alert.suppress = 0
alert.track = 1
alert.expires = 24h
counttype = number of events
cron_schedule = */10 * * * *
allow_skew = 50%
schedule_window = auto
description = Allow Incoming Connections by Port or Application on Windows Firewall
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (CommandLine="*netsh firewall add*") | stats values(*) AS * by _time | search NOT [| inputlookup Netsh_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.lateral_movement,sigma_tag=attack.command_and_control,sigma_tag=attack.t1090,level=medium"
```
