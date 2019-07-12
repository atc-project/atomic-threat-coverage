| Title                | Enabled User Right in AD to Control User Objects                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects scenario where if a user is assigned the SeEnableDelegationPrivilege right in Active Directory it would allow control of other AD user objects.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1078: Valid Accounts](https://attack.mitre.org/techniques/T1078)</li></ul>  |
| Data Needed          | <ul><li>[DN_0066_4704_user_right_was_assigned](../Data_Needed/DN_0066_4704_user_right_was_assigned.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1078: Valid Accounts](../Triggers/T1078.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           | <ul><li>[https://www.harmj0y.net/blog/activedirectory/the-most-dangerous-user-right-you-probably-have-never-heard-of/](https://www.harmj0y.net/blog/activedirectory/the-most-dangerous-user-right-you-probably-have-never-heard-of/)</li></ul>  |
| Author               | @neu5ron |


## Detection Rules

### Sigma rule

```
title: Enabled User Right in AD to Control User Objects
description: Detects scenario where if a user is assigned the SeEnableDelegationPrivilege right in Active Directory it would allow control of other AD user objects.
tags:
    - attack.privilege_escalation
    - attack.t1078
references:
    - https://www.harmj0y.net/blog/activedirectory/the-most-dangerous-user-right-you-probably-have-never-heard-of/
author: '@neu5ron'
logsource:
    product: windows
    service: security
    definition: 'Requirements: Audit Policy : Policy Change > Audit Authorization Policy Change, Group Policy : Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Policy Change\Audit Authorization Policy Change'
detection:
    selection:
        EventID: 4704
    keywords:
        - 'SeEnableDelegationPrivilege'
    condition: all of them
falsepositives: 
    - Unknown
level: high

```





### es-qs
    
```
(EventID:"4704" AND "SeEnableDelegationPrivilege")
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Enabled-User-Right-in-AD-to-Control-User-Objects <<EOF\n{\n  "metadata": {\n    "title": "Enabled User Right in AD to Control User Objects",\n    "description": "Detects scenario where if a user is assigned the SeEnableDelegationPrivilege right in Active Directory it would allow control of other AD user objects.",\n    "tags": [\n      "attack.privilege_escalation",\n      "attack.t1078"\n    ],\n    "query": "(EventID:\\"4704\\" AND \\"SeEnableDelegationPrivilege\\")"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"4704\\" AND \\"SeEnableDelegationPrivilege\\")",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Enabled User Right in AD to Control User Objects\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"4704" AND "SeEnableDelegationPrivilege")
```


### splunk
    
```
(EventID="4704" "SeEnableDelegationPrivilege")
```


### logpoint
    
```
(EventID="4704" "SeEnableDelegationPrivilege")
```


### grep
    
```
grep -P '^(?:.*(?=.*4704)(?=.*SeEnableDelegationPrivilege))'
```



