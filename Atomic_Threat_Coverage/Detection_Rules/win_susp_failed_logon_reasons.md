| Title                | Account Tampering - Suspicious Failed Logon Reasons                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | This method uses uncommon error codes on failed logons to determine suspicious activity and tampering with accounts that have been disabled or somehow restricted.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1078: Valid Accounts](https://attack.mitre.org/techniques/T1078)</li></ul>  |
| Data Needed          | <ul><li>[DN_0079_4776_computer_attempted_to_validate_the_credentials_for_an_account](../Data_Needed/DN_0079_4776_computer_attempted_to_validate_the_credentials_for_an_account.md)</li><li>[DN_0057_4625_account_failed_to_logon](../Data_Needed/DN_0057_4625_account_failed_to_logon.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1078: Valid Accounts](../Triggers/T1078.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>User using a disabled account</li></ul>  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           | <ul><li>[https://twitter.com/SBousseaden/status/1101431884540710913](https://twitter.com/SBousseaden/status/1101431884540710913)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Account Tampering - Suspicious Failed Logon Reasons
id: 9eb99343-d336-4020-a3cd-67f3819e68ee
description: This method uses uncommon error codes on failed logons to determine suspicious activity and tampering with accounts that have been disabled or somehow
    restricted.
author: Florian Roth
modified: 2019/03/01
references:
    - https://twitter.com/SBousseaden/status/1101431884540710913
tags:
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1078
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 4625
            - 4776
        Status:
            - '0xC0000072'  # User logon to account disabled by administrator
            - '0xC000006F'  # User logon outside authorized hours
            - '0xC0000070'  # User logon from unauthorized workstation
            - '0xC0000413'  # Logon Failure: The machine you are logging onto is protected by an authentication firewall. The specified account is not allowed to authenticate to the machine
            - '0xC000018C'  # The logon request failed because the trust relationship between the primary domain and the trusted domain failed
            - '0xC000015B'  # The user has not been granted the requested logon type (aka logon right) at this machine
    condition: selection
falsepositives:
    - User using a disabled account
level: high

```





### splunk
    
```
((EventID="4625" OR EventID="4776") (Status="0xC0000072" OR Status="0xC000006F" OR Status="0xC0000070" OR Status="0xC0000413" OR Status="0xC000018C" OR Status="0xC000015B"))
```






### Saved Search for Splunk

```
b'# Generated with Sigma2SplunkAlert\n[Account Tampering - Suspicious Failed Logon Reasons]\naction.email = 1\naction.email.subject.alert = Splunk Alert: $name$\naction.email.to = test@test.de\naction.email.message.alert = Splunk Alert $name$ triggered \\\nList of interesting fields:   \\\ntitle: Account Tampering - Suspicious Failed Logon Reasons status:  \\\ndescription: This method uses uncommon error codes on failed logons to determine suspicious activity and tampering with accounts that have been disabled or somehow restricted. \\\nreferences: [\'https://twitter.com/SBousseaden/status/1101431884540710913\'] \\\ntags: [\'attack.persistence\', \'attack.privilege_escalation\', \'attack.t1078\'] \\\nauthor: Florian Roth \\\ndate:  \\\nfalsepositives: [\'User using a disabled account\'] \\\nlevel: high\naction.email.useNSSubject = 1\nalert.severity = 1\nalert.suppress = 0\nalert.track = 1\nalert.expires = 24h\ncounttype = number of events\ncron_schedule = */10 * * * *\nallow_skew = 50%\nschedule_window = auto\ndescription = This method uses uncommon error codes on failed logons to determine suspicious activity and tampering with accounts that have been disabled or somehow restricted.\ndispatch.earliest_time = -10m\ndispatch.latest_time = now\nenableSched = 1\nquantity = 0\nrelation = greater than\nrequest.ui_dispatch_app = sigma_hunting_app\nrequest.ui_dispatch_view = search\nsearch = ((EventID="4625" OR EventID="4776") (Status="0xC0000072" OR Status="0xC000006F" OR Status="0xC0000070" OR Status="0xC0000413" OR Status="0xC000018C" OR Status="0xC000015B")) | stats values(*) AS * by _time | search NOT [| inputlookup Account_Tampering_-_Suspicious_Failed_Logon_Reasons_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.persistence,sigma_tag=attack.privilege_escalation,sigma_tag=attack.t1078,level=high"\n\n\n'
```
