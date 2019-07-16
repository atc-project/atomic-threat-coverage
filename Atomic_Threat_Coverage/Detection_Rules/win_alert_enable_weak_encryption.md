| Title                | Weak Encryption Enabled and Kerberoast                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects scenario where weak encryption is enabled for a user profile which could be used for hash/password cracking.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1089: Disabling Security Tools](https://attack.mitre.org/techniques/T1089)</li></ul>  |
| Data Needed          | <ul><li>[DN_0027_4738_user_account_was_changed](../Data_Needed/DN_0027_4738_user_account_was_changed.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1089: Disabling Security Tools](../Triggers/T1089.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           | <ul><li>[https://adsecurity.org/?p=2053](https://adsecurity.org/?p=2053)</li><li>[https://www.harmj0y.net/blog/activedirectory/roasting-as-reps/](https://www.harmj0y.net/blog/activedirectory/roasting-as-reps/)</li></ul>  |
| Author               | @neu5ron |


## Detection Rules

### Sigma rule

```
title: Weak Encryption Enabled and Kerberoast
description: Detects scenario where weak encryption is enabled for a user profile which could be used for hash/password cracking.
references:
    - https://adsecurity.org/?p=2053
    - https://www.harmj0y.net/blog/activedirectory/roasting-as-reps/
author: '@neu5ron'
tags:
    - attack.defense_evasion
    - attack.t1089
logsource:
    product: windows
    service: security
    definition: 'Requirements: Audit Policy : Account Management > Audit User Account Management, Group Policy : Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Account Management\Audit User Account Management'
detection:
    selection:
        EventID: 4738
    keywords:
        - 'DES'
        - 'Preauth'
        - 'Encrypted'
    filters:
        - 'Enabled'
    condition: selection and keywords and filters
falsepositives: 
    - Unknown
level: high

```





### es-qs
    
```
((EventID:"4738" AND ("DES" OR "Preauth" OR "Encrypted")) AND "Enabled")
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Weak-Encryption-Enabled-and-Kerberoast <<EOF\n{\n  "metadata": {\n    "title": "Weak Encryption Enabled and Kerberoast",\n    "description": "Detects scenario where weak encryption is enabled for a user profile which could be used for hash/password cracking.",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1089"\n    ],\n    "query": "((EventID:\\"4738\\" AND (\\"DES\\" OR \\"Preauth\\" OR \\"Encrypted\\")) AND \\"Enabled\\")"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((EventID:\\"4738\\" AND (\\"DES\\" OR \\"Preauth\\" OR \\"Encrypted\\")) AND \\"Enabled\\")",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Weak Encryption Enabled and Kerberoast\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((EventID:"4738" AND ("DES" OR "Preauth" OR "Encrypted")) AND "Enabled")
```


### splunk
    
```
((EventID="4738" ("DES" OR "Preauth" OR "Encrypted")) "Enabled")
```


### logpoint
    
```
((EventID="4738" ("DES" OR "Preauth" OR "Encrypted")) "Enabled")
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*4738)(?=.*(?:.*(?:.*DES|.*Preauth|.*Encrypted)))))(?=.*Enabled))'
```



