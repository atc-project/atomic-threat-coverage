| Title                | Taskmgr as LOCAL_SYSTEM                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects the creation of taskmgr.exe process in context of LOCAL_SYSTEM                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul></ul>  |
| ATT&amp;CK Technique | <ul></ul>                             |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              |  There is no Trigger for this technique yet.  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>Unkown</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Taskmgr as LOCAL_SYSTEM
status: experimental
description: Detects the creation of taskmgr.exe process in context of LOCAL_SYSTEM
author: Florian Roth
date: 2018/03/18
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1
        User: 'NT AUTHORITY\SYSTEM'
        Image: '*\taskmgr.exe'
    condition: selection
falsepositives:
    - Unkown
level: high

```





### Kibana query

```
(EventID:"1" AND User:"NT\\ AUTHORITY\\\\SYSTEM" AND Image.keyword:*\\\\taskmgr.exe)
```





### X-Pack Watcher

```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Taskmgr-as-LOCAL_SYSTEM <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"1\\" AND User:\\"NT\\\\ AUTHORITY\\\\\\\\SYSTEM\\" AND Image.keyword:*\\\\\\\\taskmgr.exe)",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Taskmgr as LOCAL_SYSTEM\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```





### Graylog

```
(EventID:"1" AND User:"NT AUTHORITY\\\\SYSTEM" AND Image:"*\\\\taskmgr.exe")
```





### Splunk

```
(EventID="1" User="NT AUTHORITY\\\\SYSTEM" Image="*\\\\taskmgr.exe")
```





### Logpoint

```
(EventID="1" User="NT AUTHORITY\\\\SYSTEM" Image="*\\\\taskmgr.exe")
```





### Grep

```
grep -P '^(?:.*(?=.*1)(?=.*NT AUTHORITY\\SYSTEM)(?=.*.*\\taskmgr\\.exe))'
```





### Fieldlist

```
EventID\nImage\nUser
```

