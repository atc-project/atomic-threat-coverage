| Title                | Suspicious Kerberos RC4 Ticket Encryption                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects service ticket requests using RC4 encryption type                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1208: Kerberoasting](https://attack.mitre.org/techniques/T1208)</li></ul>  |
| Data Needed          | <ul><li>[DN_0077_4769_kerberos_service_ticket_was_requested](../Data_Needed/DN_0077_4769_kerberos_service_ticket_was_requested.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1208: Kerberoasting](../Triggers/T1208.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Service accounts used on legacy systems (e.g. NetApp)</li><li>Windows Domains with DFL 2003 and legacy systems</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://adsecurity.org/?p=3458](https://adsecurity.org/?p=3458)</li><li>[https://www.trimarcsecurity.com/single-post/TrimarcResearch/Detecting-Kerberoasting-Activity](https://www.trimarcsecurity.com/single-post/TrimarcResearch/Detecting-Kerberoasting-Activity)</li></ul>  |
| Author               |  Author of this Detection Rule haven't introduced himself  |


## Detection Rules

### Sigma rule

```
title: Suspicious Kerberos RC4 Ticket Encryption
id: 496a0e47-0a33-4dca-b009-9e6ca3591f39
status: experimental
references:
    - https://adsecurity.org/?p=3458
    - https://www.trimarcsecurity.com/single-post/TrimarcResearch/Detecting-Kerberoasting-Activity
tags:
    - attack.credential_access
    - attack.t1208
description: Detects service ticket requests using RC4 encryption type
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4769
        TicketOptions: '0x40810000'
        TicketEncryptionType: '0x17'
    reduction:
        - ServiceName: '$*'
    condition: selection and not reduction
falsepositives:
    - Service accounts used on legacy systems (e.g. NetApp)
    - Windows Domains with DFL 2003 and legacy systems
level: medium

```





### splunk
    
```
((EventID="4769" TicketOptions="0x40810000" TicketEncryptionType="0x17") NOT (ServiceName="$*"))
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Suspicious Kerberos RC4 Ticket Encryption]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Suspicious Kerberos RC4 Ticket Encryption status: experimental \
description: Detects service ticket requests using RC4 encryption type \
references: ['https://adsecurity.org/?p=3458', 'https://www.trimarcsecurity.com/single-post/TrimarcResearch/Detecting-Kerberoasting-Activity'] \
tags: ['attack.credential_access', 'attack.t1208'] \
author:  \
date:  \
falsepositives: ['Service accounts used on legacy systems (e.g. NetApp)', 'Windows Domains with DFL 2003 and legacy systems'] \
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
description = Detects service ticket requests using RC4 encryption type
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = ((EventID="4769" TicketOptions="0x40810000" TicketEncryptionType="0x17") NOT (ServiceName="$*")) | stats values(*) AS * by _time | search NOT [| inputlookup Suspicious_Kerberos_RC4_Ticket_Encryption_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.credential_access,sigma_tag=attack.t1208,level=medium"
```
