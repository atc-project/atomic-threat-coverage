| Title                | Scanner PoC for CVE-2019-0708 RDP RCE vuln                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects the use of a scanner by zerosum0x0 that discovers targets vulnerable to  CVE-2019-0708 RDP RCE aka BlueKeep                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1210: Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210)</li></ul>  |
| Data Needed          | <ul><li>[DN_0057_4625_account_failed_to_logon](../Data_Needed/DN_0057_4625_account_failed_to_logon.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1210: Exploitation of Remote Services](../Triggers/T1210.md)</li></ul>  |
| Severity Level       | critical |
| False Positives      | <ul><li>Unlikely</li></ul>  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           | <ul><li>[https://twitter.com/AdamTheAnalyst/status/1134394070045003776](https://twitter.com/AdamTheAnalyst/status/1134394070045003776)</li><li>[https://github.com/zerosum0x0/CVE-2019-0708](https://github.com/zerosum0x0/CVE-2019-0708)</li></ul>  |
| Author               | Florian Roth (rule), Adam Bradbury (idea) |
| Other Tags           | <ul><li>car.2013-07-002</li><li>car.2013-07-002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Scanner PoC for CVE-2019-0708 RDP RCE vuln
id: 8400629e-79a9-4737-b387-5db940ab2367
description: Detects the use of a scanner by zerosum0x0 that discovers targets vulnerable to  CVE-2019-0708 RDP RCE aka BlueKeep
references:
    - https://twitter.com/AdamTheAnalyst/status/1134394070045003776
    - https://github.com/zerosum0x0/CVE-2019-0708
tags:
    - attack.lateral_movement
    - attack.t1210
    - car.2013-07-002
author: Florian Roth (rule), Adam Bradbury (idea)
date: 2019/06/02
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
        AccountName: AAAAAAA
    condition: selection
falsepositives:
    - Unlikely
level: critical

```





### splunk
    
```
(EventID="4625" AccountName="AAAAAAA")
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Scanner PoC for CVE-2019-0708 RDP RCE vuln]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Scanner PoC for CVE-2019-0708 RDP RCE vuln status:  \
description: Detects the use of a scanner by zerosum0x0 that discovers targets vulnerable to  CVE-2019-0708 RDP RCE aka BlueKeep \
references: ['https://twitter.com/AdamTheAnalyst/status/1134394070045003776', 'https://github.com/zerosum0x0/CVE-2019-0708'] \
tags: ['attack.lateral_movement', 'attack.t1210', 'car.2013-07-002'] \
author: Florian Roth (rule), Adam Bradbury (idea) \
date:  \
falsepositives: ['Unlikely'] \
level: critical
action.email.useNSSubject = 1
alert.severity = 1
alert.suppress = 0
alert.track = 1
alert.expires = 24h
counttype = number of events
cron_schedule = */10 * * * *
allow_skew = 50%
schedule_window = auto
description = Detects the use of a scanner by zerosum0x0 that discovers targets vulnerable to  CVE-2019-0708 RDP RCE aka BlueKeep
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (EventID="4625" AccountName="AAAAAAA") | stats values(*) AS * by _time | search NOT [| inputlookup Scanner_PoC_for_CVE-2019-0708_RDP_RCE_vuln_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.lateral_movement,sigma_tag=attack.t1210,sigma_tag=car.2013-07-002,level=critical"
```
