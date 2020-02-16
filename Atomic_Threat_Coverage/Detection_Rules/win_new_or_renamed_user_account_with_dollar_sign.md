| Title                | New (or renamed) user account with '$' in attribute 'SamAccountName'.                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects possible bypass EDR and SIEM via abnormal user account name.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1036: Masquerading](https://attack.mitre.org/techniques/T1036)</li></ul>  |
| Data Needed          | <ul><li>[DN_0086_4720_user_account_was_created](../Data_Needed/DN_0086_4720_user_account_was_created.md)</li></ul>  |
| Trigger              | <ul><li>[T1036: Masquerading](../Triggers/T1036.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Unkown</li></ul>  |
| Development Status   | experimental |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Ilyas Ochkov, oscd.community |


## Detection Rules

### Sigma rule

```
title: New (or renamed) user account with '$' in attribute 'SamAccountName'.
id: cfeed607-6aa4-4bbd-9627-b637deb723c8
status: experimental
description: Detects possible bypass EDR and SIEM via abnormal user account name.
tags:
    - attack.defense_evasion
    - attack.t1036
author: Ilyas Ochkov, oscd.community
date: 2019/10/25
modified: 2019/11/13
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 
            - 4720 # create user
            - 4781 # rename user
        UserName|contains: '$'    #SamAccountName
    condition: selection
fields:
    - EventID
    - UserName
    - SubjectAccountName
falsepositives:
    - Unkown
level: medium

```





### es-qs
    
```
(EventID:("4720" OR "4781") AND UserName.keyword:*$*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/New-or-renamed-user-account-with-\'$\'-in-attribute-\'SamAccountName\'. <<EOF\n{\n  "metadata": {\n    "title": "New (or renamed) user account with \'$\' in attribute \'SamAccountName\'.",\n    "description": "Detects possible bypass EDR and SIEM via abnormal user account name.",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1036"\n    ],\n    "query": "(EventID:(\\"4720\\" OR \\"4781\\") AND UserName.keyword:*$*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:(\\"4720\\" OR \\"4781\\") AND UserName.keyword:*$*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'New (or renamed) user account with \'$\' in attribute \'SamAccountName\'.\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n           EventID = {{_source.EventID}}\\n          UserName = {{_source.UserName}}\\nSubjectAccountName = {{_source.SubjectAccountName}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:("4720" "4781") AND UserName.keyword:*$*)
```


### splunk
    
```
((EventID="4720" OR EventID="4781") UserName="*$*") | table EventID,UserName,SubjectAccountName
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id IN ["4720", "4781"] (caller_user="*$*" OR target_user="*$*" OR user="*$*" OR member="*$*"))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*4720|.*4781))(?=.*.*\\$.*))'
```



