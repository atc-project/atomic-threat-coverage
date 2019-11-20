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
b'# Generated with Sigma2SplunkAlert\n[Password Change on Directory Service Restore Mode (DSRM) Account]\naction.email = 1\naction.email.subject.alert = Splunk Alert: $name$\naction.email.to = test@test.de\naction.email.message.alert = Splunk Alert $name$ triggered \\\nList of interesting fields:   \\\ntitle: Password Change on Directory Service Restore Mode (DSRM) Account status: stable \\\ndescription: The Directory Service Restore Mode (DSRM) account is a local administrator account on Domain Controllers. Attackers may change the password to gain persistence. \\\nreferences: [\'https://adsecurity.org/?p=1714\'] \\\ntags: [\'attack.persistence\', \'attack.privilege_escalation\', \'attack.t1098\'] \\\nauthor: Thomas Patzke \\\ndate:  \\\nfalsepositives: [\'Initial installation of a domain controller\'] \\\nlevel: high\naction.email.useNSSubject = 1\nalert.severity = 1\nalert.suppress = 0\nalert.track = 1\nalert.expires = 24h\ncounttype = number of events\ncron_schedule = */10 * * * *\nallow_skew = 50%\nschedule_window = auto\ndescription = The Directory Service Restore Mode (DSRM) account is a local administrator account on Domain Controllers. Attackers may change the password to gain persistence.\ndispatch.earliest_time = -10m\ndispatch.latest_time = now\nenableSched = 1\nquantity = 0\nrelation = greater than\nrequest.ui_dispatch_app = sigma_hunting_app\nrequest.ui_dispatch_view = search\nsearch = EventID="4794" | stats values(*) AS * by _time | search NOT [| inputlookup Password_Change_on_Directory_Service_Restore_Mode_DSRM_Account_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.persistence,sigma_tag=attack.privilege_escalation,sigma_tag=attack.t1098,level=high"\n\n\n'
```
