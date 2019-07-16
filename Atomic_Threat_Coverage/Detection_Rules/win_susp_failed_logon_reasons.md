| Title                | Account Tampering - Suspicious Failed Logon Reasons                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | This method uses uncommon error codes on failed logons to determine suspicious activity and tampering with accounts that have been disabled or somehow restricted.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1078: Valid Accounts](https://attack.mitre.org/techniques/T1078)</li></ul>  |
| Data Needed          | <ul><li>[DN_0057_4625_account_failed_to_logon](../Data_Needed/DN_0057_4625_account_failed_to_logon.md)</li><li>[DN_0079_4776_computer_attempted_to_validate_the_credentials_for_an_account](../Data_Needed/DN_0079_4776_computer_attempted_to_validate_the_credentials_for_an_account.md)</li></ul>  |
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
(EventID:("4625" "4776") AND Status:("0xC0000072" "0xC000006F" "0xC0000070" "0xC0000413" "0xC000018C" "0xC000015B"))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Account-Tampering---Suspicious-Failed-Logon-Reasons <<EOF\n{\n  "metadata": {\n    "title": "Account Tampering - Suspicious Failed Logon Reasons",\n    "description": "This method uses uncommon error codes on failed logons to determine suspicious activity and tampering with accounts that have been disabled or somehow restricted.",\n    "tags": [\n      "attack.persistence",\n      "attack.privilege_escalation",\n      "attack.t1078"\n    ],\n    "query": "(EventID:(\\"4625\\" \\"4776\\") AND Status:(\\"0xC0000072\\" \\"0xC000006F\\" \\"0xC0000070\\" \\"0xC0000413\\" \\"0xC000018C\\" \\"0xC000015B\\"))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:(\\"4625\\" \\"4776\\") AND Status:(\\"0xC0000072\\" \\"0xC000006F\\" \\"0xC0000070\\" \\"0xC0000413\\" \\"0xC000018C\\" \\"0xC000015B\\"))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Account Tampering - Suspicious Failed Logon Reasons\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:("4625" "4776") AND Status:("0xC0000072" "0xC000006F" "0xC0000070" "0xC0000413" "0xC000018C" "0xC000015B"))
```


### splunk
    
```
((EventID="4625" OR EventID="4776") (Status="0xC0000072" OR Status="0xC000006F" OR Status="0xC0000070" OR Status="0xC0000413" OR Status="0xC000018C" OR Status="0xC000015B"))
```


### logpoint
    
```
(EventID IN ["4625", "4776"] Status IN ["0xC0000072", "0xC000006F", "0xC0000070", "0xC0000413", "0xC000018C", "0xC000015B"])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*4625|.*4776))(?=.*(?:.*0xC0000072|.*0xC000006F|.*0xC0000070|.*0xC0000413|.*0xC000018C|.*0xC000015B)))'
```



