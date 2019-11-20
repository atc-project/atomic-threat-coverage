| Title                | Netsh RDP Port Forwarding                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects netsh commands that configure a port forwarding of port 3389 used for RDP                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1021: Remote Services](https://attack.mitre.org/techniques/T1021)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1021: Remote Services](../Triggers/T1021.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Legitimate administration</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html](https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html)</li></ul>  |
| Author               | Florian Roth |
| Other Tags           | <ul><li>car.2013-07-002</li><li>car.2013-07-002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Netsh RDP Port Forwarding
id: 782d6f3e-4c5d-4b8c-92a3-1d05fed72e63
description: Detects netsh commands that configure a port forwarding of port 3389 used for RDP
references:
    - https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html
date: 2019/01/29
tags:
    - attack.lateral_movement
    - attack.t1021
    - car.2013-07-002
status: experimental
author: Florian Roth
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - netsh i* p*=3389 c*
    condition: selection
falsepositives:
    - Legitimate administration
level: high

```





### splunk
    
```
(CommandLine="netsh i* p*=3389 c*")
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Netsh RDP Port Forwarding]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Netsh RDP Port Forwarding status: experimental \
description: Detects netsh commands that configure a port forwarding of port 3389 used for RDP \
references: ['https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html'] \
tags: ['attack.lateral_movement', 'attack.t1021', 'car.2013-07-002'] \
author: Florian Roth \
date:  \
falsepositives: ['Legitimate administration'] \
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
description = Detects netsh commands that configure a port forwarding of port 3389 used for RDP
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (CommandLine="netsh i* p*=3389 c*") | stats values(*) AS * by _time | search NOT [| inputlookup Netsh_RDP_Port_Forwarding_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.lateral_movement,sigma_tag=attack.t1021,sigma_tag=car.2013-07-002,level=high"
```
