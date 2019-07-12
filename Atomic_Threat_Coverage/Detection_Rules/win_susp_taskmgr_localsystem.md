| Title                | Taskmgr as LOCAL_SYSTEM                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects the creation of taskmgr.exe process in context of LOCAL_SYSTEM                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1036: Masquerading](https://attack.mitre.org/techniques/T1036)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1036: Masquerading](../Triggers/T1036.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Unkown</li></ul>  |
| Development Status   | experimental |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Taskmgr as LOCAL_SYSTEM
status: experimental
description: Detects the creation of taskmgr.exe process in context of LOCAL_SYSTEM
tags:
    - attack.defense_evasion
    - attack.t1036
author: Florian Roth
date: 2018/03/18
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        User: NT AUTHORITY\SYSTEM
        Image: '*\taskmgr.exe'
    condition: selection
falsepositives:
    - Unkown
level: high

```





### es-qs
    
```
(User:"NT\\ AUTHORITY\\\\SYSTEM" AND Image.keyword:*\\\\taskmgr.exe)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Taskmgr-as-LOCAL_SYSTEM <<EOF\n{\n  "metadata": {\n    "title": "Taskmgr as LOCAL_SYSTEM",\n    "description": "Detects the creation of taskmgr.exe process in context of LOCAL_SYSTEM",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1036"\n    ],\n    "query": "(User:\\"NT\\\\ AUTHORITY\\\\\\\\SYSTEM\\" AND Image.keyword:*\\\\\\\\taskmgr.exe)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(User:\\"NT\\\\ AUTHORITY\\\\\\\\SYSTEM\\" AND Image.keyword:*\\\\\\\\taskmgr.exe)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Taskmgr as LOCAL_SYSTEM\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(User:"NT AUTHORITY\\\\SYSTEM" AND Image:"*\\\\taskmgr.exe")
```


### splunk
    
```
(User="NT AUTHORITY\\\\SYSTEM" Image="*\\\\taskmgr.exe")
```


### logpoint
    
```
(User="NT AUTHORITY\\\\SYSTEM" Image="*\\\\taskmgr.exe")
```


### grep
    
```
grep -P '^(?:.*(?=.*NT AUTHORITY\\SYSTEM)(?=.*.*\\taskmgr\\.exe))'
```



