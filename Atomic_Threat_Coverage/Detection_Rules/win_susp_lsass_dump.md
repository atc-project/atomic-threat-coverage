| Title                | Password Dumper Activity on LSASS                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects process handle on LSASS process with certain access mask and object type SAM_DOMAIN                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1003: Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| Data Needed          | <ul><li>[DN_0058_4656_handle_to_an_object_was_requested](../Data_Needed/DN_0058_4656_handle_to_an_object_was_requested.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1003: Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Unkown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://twitter.com/jackcr/status/807385668833968128](https://twitter.com/jackcr/status/807385668833968128)</li></ul>  |
| Author               |  Author of this Detection Rule haven't introduced himself  |


## Detection Rules

### Sigma rule

```
title: Password Dumper Activity on LSASS
id: aa1697b7-d611-4f9a-9cb2-5125b4ccfd5c
description: Detects process handle on LSASS process with certain access mask and object type SAM_DOMAIN
status: experimental
references:
    - https://twitter.com/jackcr/status/807385668833968128
tags:
    - attack.credential_access
    - attack.t1003
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4656
        ProcessName: 'C:\Windows\System32\lsass.exe'
        AccessMask: '0x705'
        ObjectType: 'SAM_DOMAIN'
    condition: selection
falsepositives:
    - Unkown
level: high

```





### splunk
    
```
(EventID="4656" ProcessName="C:\\\\Windows\\\\System32\\\\lsass.exe" AccessMask="0x705" ObjectType="SAM_DOMAIN")
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Password Dumper Activity on LSASS]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Password Dumper Activity on LSASS status: experimental \
description: Detects process handle on LSASS process with certain access mask and object type SAM_DOMAIN \
references: ['https://twitter.com/jackcr/status/807385668833968128'] \
tags: ['attack.credential_access', 'attack.t1003'] \
author:  \
date:  \
falsepositives: ['Unkown'] \
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
description = Detects process handle on LSASS process with certain access mask and object type SAM_DOMAIN
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (EventID="4656" ProcessName="C:\\Windows\\System32\\lsass.exe" AccessMask="0x705" ObjectType="SAM_DOMAIN") | stats values(*) AS * by _time | search NOT [| inputlookup Password_Dumper_Activity_on_LSASS_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.credential_access,sigma_tag=attack.t1003,level=high"
```
