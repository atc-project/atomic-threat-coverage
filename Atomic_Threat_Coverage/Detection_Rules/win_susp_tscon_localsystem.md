| Title                | Suspicious TSCON Start                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a tscon.exe start as LOCAL SYSTEM                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0011: Command and Control](https://attack.mitre.org/tactics/TA0011)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1219: Remote Access Tools](https://attack.mitre.org/techniques/T1219)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1219: Remote Access Tools](../Triggers/T1219.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[http://www.korznikov.com/2017/03/0-day-or-feature-privilege-escalation.html](http://www.korznikov.com/2017/03/0-day-or-feature-privilege-escalation.html)</li><li>[https://medium.com/@networksecurity/rdp-hijacking-how-to-hijack-rds-and-remoteapp-sessions-transparently-to-move-through-an-da2a1e73a5f6](https://medium.com/@networksecurity/rdp-hijacking-how-to-hijack-rds-and-remoteapp-sessions-transparently-to-move-through-an-da2a1e73a5f6)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Suspicious TSCON Start
status: experimental
description: Detects a tscon.exe start as LOCAL SYSTEM
references:
    - http://www.korznikov.com/2017/03/0-day-or-feature-privilege-escalation.html
    - https://medium.com/@networksecurity/rdp-hijacking-how-to-hijack-rds-and-remoteapp-sessions-transparently-to-move-through-an-da2a1e73a5f6
author: Florian Roth
date: 2018/03/17
tags:
    - attack.command_and_control
    - attack.t1219
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        User: NT AUTHORITY\SYSTEM
        Image: '*\tscon.exe'
    condition: selection
falsepositives:
    - Unknown
level: high

```





### es-qs
    
```
(User:"NT\\ AUTHORITY\\\\SYSTEM" AND Image.keyword:*\\\\tscon.exe)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Suspicious-TSCON-Start <<EOF\n{\n  "metadata": {\n    "title": "Suspicious TSCON Start",\n    "description": "Detects a tscon.exe start as LOCAL SYSTEM",\n    "tags": [\n      "attack.command_and_control",\n      "attack.t1219"\n    ],\n    "query": "(User:\\"NT\\\\ AUTHORITY\\\\\\\\SYSTEM\\" AND Image.keyword:*\\\\\\\\tscon.exe)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(User:\\"NT\\\\ AUTHORITY\\\\\\\\SYSTEM\\" AND Image.keyword:*\\\\\\\\tscon.exe)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Suspicious TSCON Start\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(User:"NT AUTHORITY\\\\SYSTEM" AND Image:"*\\\\tscon.exe")
```


### splunk
    
```
(User="NT AUTHORITY\\\\SYSTEM" Image="*\\\\tscon.exe")
```


### logpoint
    
```
(User="NT AUTHORITY\\\\SYSTEM" Image="*\\\\tscon.exe")
```


### grep
    
```
grep -P '^(?:.*(?=.*NT AUTHORITY\\SYSTEM)(?=.*.*\\tscon\\.exe))'
```



