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
b'# Generated with Sigma2SplunkAlert\n[Scanner PoC for CVE-2019-0708 RDP RCE vuln]\naction.email = 1\naction.email.subject.alert = Splunk Alert: $name$\naction.email.to = test@test.de\naction.email.message.alert = Splunk Alert $name$ triggered \\\nList of interesting fields:   \\\ntitle: Scanner PoC for CVE-2019-0708 RDP RCE vuln status:  \\\ndescription: Detects the use of a scanner by zerosum0x0 that discovers targets vulnerable to  CVE-2019-0708 RDP RCE aka BlueKeep \\\nreferences: [\'https://twitter.com/AdamTheAnalyst/status/1134394070045003776\', \'https://github.com/zerosum0x0/CVE-2019-0708\'] \\\ntags: [\'attack.lateral_movement\', \'attack.t1210\', \'car.2013-07-002\'] \\\nauthor: Florian Roth (rule), Adam Bradbury (idea) \\\ndate:  \\\nfalsepositives: [\'Unlikely\'] \\\nlevel: critical\naction.email.useNSSubject = 1\nalert.severity = 1\nalert.suppress = 0\nalert.track = 1\nalert.expires = 24h\ncounttype = number of events\ncron_schedule = */10 * * * *\nallow_skew = 50%\nschedule_window = auto\ndescription = Detects the use of a scanner by zerosum0x0 that discovers targets vulnerable to  CVE-2019-0708 RDP RCE aka BlueKeep\ndispatch.earliest_time = -10m\ndispatch.latest_time = now\nenableSched = 1\nquantity = 0\nrelation = greater than\nrequest.ui_dispatch_app = sigma_hunting_app\nrequest.ui_dispatch_view = search\nsearch = (EventID="4625" AccountName="AAAAAAA") | stats values(*) AS * by _time | search NOT [| inputlookup Scanner_PoC_for_CVE-2019-0708_RDP_RCE_vuln_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.lateral_movement,sigma_tag=attack.t1210,sigma_tag=car.2013-07-002,level=critical"\n\n\n'
```
