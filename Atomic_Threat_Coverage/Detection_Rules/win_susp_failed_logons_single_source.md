| Title                | Multiple Failed Logins with Different Accounts from Single Source System                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious failed logins with different user accounts from a single source system                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1078: Valid Accounts](https://attack.mitre.org/techniques/T1078)</li></ul>  |
| Data Needed          | <ul><li>[DN_0079_4776_computer_attempted_to_validate_the_credentials_for_an_account](../Data_Needed/DN_0079_4776_computer_attempted_to_validate_the_credentials_for_an_account.md)</li><li>[DN_0057_4625_account_failed_to_logon](../Data_Needed/DN_0057_4625_account_failed_to_logon.md)</li><li>[DN_0041_529_logon_failure](../Data_Needed/DN_0041_529_logon_failure.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1078: Valid Accounts](../Triggers/T1078.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Terminal servers</li><li>Jump servers</li><li>Other multiuser systems like Citrix server farms</li><li>Workstations with frequently changing users</li></ul>  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Multiple Failed Logins with Different Accounts from Single Source System
id: e98374a6-e2d9-4076-9b5c-11bdb2569995
description: Detects suspicious failed logins with different user accounts from a single source system
author: Florian Roth
tags:
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1078
logsource:
    product: windows
    service: security
detection:
    selection1:
        EventID:
            - 529
            - 4625
        UserName: '*'
        WorkstationName: '*'
    selection2:
        EventID: 4776
        UserName: '*'
        Workstation: '*'
    timeframe: 24h 
    condition:
        - selection1 | count(UserName) by WorkstationName > 3
        - selection2 | count(UserName) by Workstation > 3
falsepositives:
    - Terminal servers
    - Jump servers
    - Other multiuser systems like Citrix server farms
    - Workstations with frequently changing users 
level: medium



```





### splunk
    
```
((EventID="529" OR EventID="4625") UserName="*" WorkstationName="*") | eventstats dc(UserName) as val by WorkstationName | search val > 3
```






### Saved Search for Splunk

```
b'# Generated with Sigma2SplunkAlert\n[Multiple Failed Logins with Different Accounts from Single Source System]\naction.email = 1\naction.email.subject.alert = Splunk Alert: $name$\naction.email.to = test@test.de\naction.email.message.alert = Splunk Alert $name$ triggered \\\nList of interesting fields:   \\\ntitle: Multiple Failed Logins with Different Accounts from Single Source System status:  \\\ndescription: Detects suspicious failed logins with different user accounts from a single source system \\\nreferences:  \\\ntags: [\'attack.persistence\', \'attack.privilege_escalation\', \'attack.t1078\'] \\\nauthor: Florian Roth \\\ndate:  \\\nfalsepositives: [\'Terminal servers\', \'Jump servers\', \'Other multiuser systems like Citrix server farms\', \'Workstations with frequently changing users\'] \\\nlevel: medium\naction.email.useNSSubject = 1\nalert.severity = 1\nalert.suppress = 0\nalert.track = 1\nalert.expires = 24h\ncounttype = number of events\ncron_schedule = */10 * * * *\nallow_skew = 50%\nschedule_window = auto\ndescription = Detects suspicious failed logins with different user accounts from a single source system\ndispatch.earliest_time = -10m\ndispatch.latest_time = now\nenableSched = 1\nquantity = 0\nrelation = greater than\nrequest.ui_dispatch_app = sigma_hunting_app\nrequest.ui_dispatch_view = search\nsearch = ((EventID="529" OR EventID="4625") UserName="*" WorkstationName="*") | eventstats dc(UserName) as val by WorkstationName | search val > 3 | stats values(*) AS * by _time | search NOT [| inputlookup Multiple_Failed_Logins_with_Different_Accounts_from_Single_Source_System_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.persistence,sigma_tag=attack.privilege_escalation,sigma_tag=attack.t1078,level=medium"\n\n\n'
```
