| Title                | Account Tampering - Suspicious Failed Logon Reasons                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | This method uses uncommon error codes on failed logons to determine suspicious activity and tampering with accounts that have been disabled or somehow restricted.                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1078: Valid Accounts](https://attack.mitre.org/techniques/T1078)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0079_4776_computer_attempted_to_validate_the_credentials_for_an_account](../Data_Needed/DN_0079_4776_computer_attempted_to_validate_the_credentials_for_an_account.md)</li><li>[DN_0057_4625_account_failed_to_logon](../Data_Needed/DN_0057_4625_account_failed_to_logon.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1078: Valid Accounts](../Triggers/T1078.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>User using a disabled account</li></ul>                                                                  |
| Development Status   |                                                                                                                                                 |
| References           | <ul><li>[https://twitter.com/SBousseaden/status/1101431884540710913](https://twitter.com/SBousseaden/status/1101431884540710913)</li></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Account Tampering - Suspicious Failed Logon Reasons
description: This method uses uncommon error codes on failed logons to determine suspicious activity and tampering with accounts that have been disabled or somehow restricted.
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





### es-qs
    
```

```


### xpack-watcher
    
```

```


### graylog
    
```
(EventID:("4625" "4776") AND Status:("0xC0000072" "0xC000006F" "0xC0000070" "0xC0000413" "0xC000018C" "0xC000015B"))
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*4625|.*4776))(?=.*(?:.*0xC0000072|.*0xC000006F|.*0xC0000070|.*0xC0000413|.*0xC000018C|.*0xC000015B)))'
```



