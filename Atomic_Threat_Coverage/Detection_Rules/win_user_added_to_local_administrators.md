| Title                    | User Added to Local Administrators       |
|:-------------------------|:------------------|
| **Description**          | This rule triggers on user accounts that are added to the local Administrators group, which could be legitimate activity or a sign of privilege escalation activity |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1078: Valid Accounts](https://attack.mitre.org/techniques/T1078)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0069_4732_member_was_added_to_security_enabled_local_group](../Data_Needed/DN_0069_4732_member_was_added_to_security_enabled_local_group.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Legitimate administrative activity</li></ul>  |
| **Development Status**   | stable |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: User Added to Local Administrators
id: c265cf08-3f99-46c1-8d59-328247057d57
description: This rule triggers on user accounts that are added to the local Administrators group, which could be legitimate activity or a sign of privilege escalation
    activity
status: stable
author: Florian Roth
date: 2017/03/14
tags:
    - attack.privilege_escalation
    - attack.t1078
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4732
    selection_group1:
        GroupName: 'Administrators'
    selection_group2:
        GroupSid: 'S-1-5-32-544'
    filter:
        SubjectUserName: '*$'
    condition: selection and (1 of selection_group*) and not filter
falsepositives:
    - Legitimate administrative activity
level: medium

```





### es-qs
    
```
((EventID:"4732" AND (GroupName:"Administrators" OR GroupSid:"S\\-1\\-5\\-32\\-544")) AND (NOT (SubjectUserName.keyword:*$)))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/c265cf08-3f99-46c1-8d59-328247057d57 <<EOF\n{\n  "metadata": {\n    "title": "User Added to Local Administrators",\n    "description": "This rule triggers on user accounts that are added to the local Administrators group, which could be legitimate activity or a sign of privilege escalation activity",\n    "tags": [\n      "attack.privilege_escalation",\n      "attack.t1078"\n    ],\n    "query": "((EventID:\\"4732\\" AND (GroupName:\\"Administrators\\" OR GroupSid:\\"S\\\\-1\\\\-5\\\\-32\\\\-544\\")) AND (NOT (SubjectUserName.keyword:*$)))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((EventID:\\"4732\\" AND (GroupName:\\"Administrators\\" OR GroupSid:\\"S\\\\-1\\\\-5\\\\-32\\\\-544\\")) AND (NOT (SubjectUserName.keyword:*$)))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'User Added to Local Administrators\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((EventID:"4732" AND (GroupName:"Administrators" OR GroupSid:"S\\-1\\-5\\-32\\-544")) AND (NOT (SubjectUserName.keyword:*$)))
```


### splunk
    
```
((EventID="4732" (GroupName="Administrators" OR GroupSid="S-1-5-32-544")) NOT (SubjectUserName="*$"))
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" (event_id="4732" event_source="Microsoft-Windows-Security-Auditing" (group_name="Administrators" OR group_sid="S-1-5-32-544"))  -(SubjectUserName="*$"))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*4732)(?=.*(?:.*(?:.*Administrators|.*S-1-5-32-544)))))(?=.*(?!.*(?:.*(?=.*.*\\$)))))'
```



