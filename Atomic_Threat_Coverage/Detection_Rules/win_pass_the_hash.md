| Title                | Pass the Hash Activity                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects the attack technique pass the hash which is used to move laterally inside the network                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1075: Pass the Hash](https://attack.mitre.org/techniques/T1075)</li></ul>  |
| Data Needed          | <ul><li>[DN_0057_4625_account_failed_to_logon](../Data_Needed/DN_0057_4625_account_failed_to_logon.md)</li><li>[DN_0004_4624_windows_account_logon](../Data_Needed/DN_0004_4624_windows_account_logon.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1075: Pass the Hash](../Triggers/T1075.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Administrator activity</li><li>Penetration tests</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/iadgov/Event-Forwarding-Guidance/tree/master/Events](https://github.com/iadgov/Event-Forwarding-Guidance/tree/master/Events)</li></ul>  |
| Author               | Ilias el Matani (rule), The Information Assurance Directorate at the NSA (method) |
| Other Tags           | <ul><li>car.2016-04-004</li><li>car.2016-04-004</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Pass the Hash Activity
id: f8d98d6c-7a07-4d74-b064-dd4a3c244528
status: experimental
description: Detects the attack technique pass the hash which is used to move laterally inside the network
references:
    - https://github.com/iadgov/Event-Forwarding-Guidance/tree/master/Events
author: Ilias el Matani (rule), The Information Assurance Directorate at the NSA (method)
tags:
    - attack.lateral_movement
    - attack.t1075
    - car.2016-04-004
logsource:
    product: windows
    service: security
    definition: The successful use of PtH for lateral movement between workstations would trigger event ID 4624, a failed logon attempt would trigger an event ID 4625
detection:
    selection:
        - EventID: 4624
          LogonType: '3'
          LogonProcessName: 'NtLmSsp'
          WorkstationName: '%Workstations%'
          ComputerName: '%Workstations%'
        - EventID: 4625
          LogonType: '3'
          LogonProcessName: 'NtLmSsp'
          WorkstationName: '%Workstations%'
          ComputerName: '%Workstations%'
    filter:
        AccountName: 'ANONYMOUS LOGON'
    condition: selection and not filter
falsepositives:
    - Administrator activity
    - Penetration tests
level: medium

```





### splunk
    
```
((LogonType="3" LogonProcessName="NtLmSsp" WorkstationName="%Workstations%" ComputerName="%Workstations%" (EventID="4624" OR EventID="4625")) NOT (AccountName="ANONYMOUS LOGON"))
```






### Saved Search for Splunk

```
b'# Generated with Sigma2SplunkAlert\n[Pass the Hash Activity]\naction.email = 1\naction.email.subject.alert = Splunk Alert: $name$\naction.email.to = test@test.de\naction.email.message.alert = Splunk Alert $name$ triggered \\\nList of interesting fields:   \\\ntitle: Pass the Hash Activity status: experimental \\\ndescription: Detects the attack technique pass the hash which is used to move laterally inside the network \\\nreferences: [\'https://github.com/iadgov/Event-Forwarding-Guidance/tree/master/Events\'] \\\ntags: [\'attack.lateral_movement\', \'attack.t1075\', \'car.2016-04-004\'] \\\nauthor: Ilias el Matani (rule), The Information Assurance Directorate at the NSA (method) \\\ndate:  \\\nfalsepositives: [\'Administrator activity\', \'Penetration tests\'] \\\nlevel: medium\naction.email.useNSSubject = 1\nalert.severity = 1\nalert.suppress = 0\nalert.track = 1\nalert.expires = 24h\ncounttype = number of events\ncron_schedule = */10 * * * *\nallow_skew = 50%\nschedule_window = auto\ndescription = Detects the attack technique pass the hash which is used to move laterally inside the network\ndispatch.earliest_time = -10m\ndispatch.latest_time = now\nenableSched = 1\nquantity = 0\nrelation = greater than\nrequest.ui_dispatch_app = sigma_hunting_app\nrequest.ui_dispatch_view = search\nsearch = ((LogonType="3" LogonProcessName="NtLmSsp" WorkstationName="%Workstations%" ComputerName="%Workstations%" (EventID="4624" OR EventID="4625")) NOT (AccountName="ANONYMOUS LOGON")) | stats values(*) AS * by _time | search NOT [| inputlookup Pass_the_Hash_Activity_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.lateral_movement,sigma_tag=attack.t1075,sigma_tag=car.2016-04-004,level=medium"\n\n\n'
```
