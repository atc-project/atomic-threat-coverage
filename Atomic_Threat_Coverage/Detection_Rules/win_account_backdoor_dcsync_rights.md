| Title                | Powerview Add-DomainObjectAcl DCSync AD Extend Right                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | backdooring domain object to grant the rights associated with DCSync to a regular user or machine account using Powerview\Add-DomainObjectAcl DCSync Extended Right cmdlet, will allow to re-obtain the pwd hashes of any user/computer                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| Data Needed          | <ul><li>[DN_0026_5136_windows_directory_service_object_was_modified](../Data_Needed/DN_0026_5136_windows_directory_service_object_was_modified.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              |  There is no documented Trigger for this Detection Rule yet  |
| Severity Level       | critical |
| False Positives      | <ul><li>New Domain Controller computer account, check user SIDs witin the value attribute of event 5136 and verify if it's a regular user or DC computer account.</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://twitter.com/menasec1/status/1111556090137903104](https://twitter.com/menasec1/status/1111556090137903104)</li><li>[https://www.specterops.io/assets/resources/an_ace_up_the_sleeve.pdf](https://www.specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)</li></ul>  |
| Author               | Samir Bousseaden |


## Detection Rules

### Sigma rule

```
title: Powerview Add-DomainObjectAcl DCSync AD Extend Right
id: 2c99737c-585d-4431-b61a-c911d86ff32f
description: backdooring domain object to grant the rights associated with DCSync to a regular user or machine account using Powerview\Add-DomainObjectAcl DCSync
    Extended Right cmdlet, will allow to re-obtain the pwd hashes of any user/computer
status: experimental
date: 2019/04/03
author: Samir Bousseaden
references:
    - https://twitter.com/menasec1/status/1111556090137903104
    - https://www.specterops.io/assets/resources/an_ace_up_the_sleeve.pdf
tags:
    - attack.credential_access
    - attack.persistence
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 5136
        LDAPDisplayName: 'ntSecurityDescriptor'
        Value: 
         - '*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*'
         - '*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*'
    condition: selection
falsepositives:
    - New Domain Controller computer account, check user SIDs witin the value attribute of event 5136 and verify if it's a regular user or DC computer account.
level: critical

```





### splunk
    
```
(EventID="5136" LDAPDisplayName="ntSecurityDescriptor" (Value="*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*" OR Value="*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*"))
```






### Saved Search for Splunk

```
b'# Generated with Sigma2SplunkAlert\n[Powerview Add-DomainObjectAcl DCSync AD Extend Right]\naction.email = 1\naction.email.subject.alert = Splunk Alert: $name$\naction.email.to = test@test.de\naction.email.message.alert = Splunk Alert $name$ triggered \\\nList of interesting fields:   \\\ntitle: Powerview Add-DomainObjectAcl DCSync AD Extend Right status: experimental \\\ndescription: backdooring domain object to grant the rights associated with DCSync to a regular user or machine account using Powerview\\Add-DomainObjectAcl DCSync Extended Right cmdlet, will allow to re-obtain the pwd hashes of any user/computer \\\nreferences: [\'https://twitter.com/menasec1/status/1111556090137903104\', \'https://www.specterops.io/assets/resources/an_ace_up_the_sleeve.pdf\'] \\\ntags: [\'attack.credential_access\', \'attack.persistence\'] \\\nauthor: Samir Bousseaden \\\ndate:  \\\nfalsepositives: ["New Domain Controller computer account, check user SIDs witin the value attribute of event 5136 and verify if it\'s a regular user or DC computer account."] \\\nlevel: critical\naction.email.useNSSubject = 1\nalert.severity = 1\nalert.suppress = 0\nalert.track = 1\nalert.expires = 24h\ncounttype = number of events\ncron_schedule = */10 * * * *\nallow_skew = 50%\nschedule_window = auto\ndescription = backdooring domain object to grant the rights associated with DCSync to a regular user or machine account using Powerview\\Add-DomainObjectAcl DCSync Extended Right cmdlet, will allow to re-obtain the pwd hashes of any user/computer\ndispatch.earliest_time = -10m\ndispatch.latest_time = now\nenableSched = 1\nquantity = 0\nrelation = greater than\nrequest.ui_dispatch_app = sigma_hunting_app\nrequest.ui_dispatch_view = search\nsearch = (EventID="5136" LDAPDisplayName="ntSecurityDescriptor" (Value="*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*" OR Value="*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*")) | stats values(*) AS * by _time | search NOT [| inputlookup Powerview_Add-DomainObjectAcl_DCSync_AD_Extend_Right_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.credential_access,sigma_tag=attack.persistence,level=critical"\n\n\n'
```
