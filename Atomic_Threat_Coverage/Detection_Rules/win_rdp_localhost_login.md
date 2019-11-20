| Title                | RDP Login from localhost                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | RDP login with localhost source address may be a tunnelled login                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1076: Remote Desktop Protocol](https://attack.mitre.org/techniques/T1076)</li></ul>  |
| Data Needed          | <ul><li>[DN_0004_4624_windows_account_logon](../Data_Needed/DN_0004_4624_windows_account_logon.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1076: Remote Desktop Protocol](../Triggers/T1076.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html](https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html)</li></ul>  |
| Author               | Thomas Patzke |
| Other Tags           | <ul><li>car.2013-07-002</li><li>car.2013-07-002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: RDP Login from localhost
id: 51e33403-2a37-4d66-a574-1fda1782cc31
description: RDP login with localhost source address may be a tunnelled login
references:
    - https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html
date: 2019/01/28
modified: 2019/01/29
tags:
    - attack.lateral_movement
    - attack.t1076
    - car.2013-07-002
status: experimental
author: Thomas Patzke
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 10
        SourceNetworkAddress:
            - "::1"
            - "127.0.0.1"
    condition: selection
falsepositives:
    - Unknown
level: high

```





### splunk
    
```
(EventID="4624" LogonType="10" (SourceNetworkAddress="::1" OR SourceNetworkAddress="127.0.0.1"))
```






### Saved Search for Splunk

```
b'# Generated with Sigma2SplunkAlert\n[RDP Login from localhost]\naction.email = 1\naction.email.subject.alert = Splunk Alert: $name$\naction.email.to = test@test.de\naction.email.message.alert = Splunk Alert $name$ triggered \\\nList of interesting fields:   \\\ntitle: RDP Login from localhost status: experimental \\\ndescription: RDP login with localhost source address may be a tunnelled login \\\nreferences: [\'https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html\'] \\\ntags: [\'attack.lateral_movement\', \'attack.t1076\', \'car.2013-07-002\'] \\\nauthor: Thomas Patzke \\\ndate:  \\\nfalsepositives: [\'Unknown\'] \\\nlevel: high\naction.email.useNSSubject = 1\nalert.severity = 1\nalert.suppress = 0\nalert.track = 1\nalert.expires = 24h\ncounttype = number of events\ncron_schedule = */10 * * * *\nallow_skew = 50%\nschedule_window = auto\ndescription = RDP login with localhost source address may be a tunnelled login\ndispatch.earliest_time = -10m\ndispatch.latest_time = now\nenableSched = 1\nquantity = 0\nrelation = greater than\nrequest.ui_dispatch_app = sigma_hunting_app\nrequest.ui_dispatch_view = search\nsearch = (EventID="4624" LogonType="10" (SourceNetworkAddress="::1" OR SourceNetworkAddress="127.0.0.1")) | stats values(*) AS * by _time | search NOT [| inputlookup RDP_Login_from_localhost_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.lateral_movement,sigma_tag=attack.t1076,sigma_tag=car.2013-07-002,level=high"\n\n\n'
```
