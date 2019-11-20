| Title                | Password Change on Directory Service Restore Mode (DSRM) Account                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | The Directory Service Restore Mode (DSRM) account is a local administrator account on Domain Controllers. Attackers may change the password to gain persistence.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1098: Account Manipulation](https://attack.mitre.org/techniques/T1098)</li></ul>  |
| Data Needed          | <ul><li>[DN_0028_4794_directory_services_restore_mode_admin_password_set](../Data_Needed/DN_0028_4794_directory_services_restore_mode_admin_password_set.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1098: Account Manipulation](../Triggers/T1098.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Initial installation of a domain controller</li></ul>  |
| Development Status   | stable |
| References           | <ul><li>[https://adsecurity.org/?p=1714](https://adsecurity.org/?p=1714)</li></ul>  |
| Author               | Thomas Patzke |


## Detection Rules

### Sigma rule

```
title: Password Change on Directory Service Restore Mode (DSRM) Account
id: 53ad8e36-f573-46bf-97e4-15ba5bf4bb51
status: stable
description: The Directory Service Restore Mode (DSRM) account is a local administrator account on Domain Controllers. Attackers may change the password to gain persistence.
references:
    - https://adsecurity.org/?p=1714
author: Thomas Patzke
tags:
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1098
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4794
    condition: selection
falsepositives:
    - Initial installation of a domain controller
level: high

```





### splunk
    
```
EventID="4794"
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Password Change on Directory Service Restore Mode (DSRM) Account]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Password Change on Directory Service Restore Mode (DSRM) Account status: stable \
description: The Directory Service Restore Mode (DSRM) account is a local administrator account on Domain Controllers. Attackers may change the password to gain persistence. \
references: ['https://adsecurity.org/?p=1714'] \
tags: ['attack.persistence', 'attack.privilege_escalation', 'attack.t1098'] \
author: Thomas Patzke \
date:  \
falsepositives: ['Initial installation of a domain controller'] \
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
description = The Directory Service Restore Mode (DSRM) account is a local administrator account on Domain Controllers. Attackers may change the password to gain persistence.
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = EventID="4794" | stats values(*) AS * by _time | search NOT [| inputlookup Password_Change_on_Directory_Service_Restore_Mode_DSRM_Account_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.persistence,sigma_tag=attack.privilege_escalation,sigma_tag=attack.t1098,level=high"
```
