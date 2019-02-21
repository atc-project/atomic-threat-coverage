| Title                | Suspicious TSCON Start                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a tscon.exe start as LOCAL SYSTEM                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul></ul>  |
| ATT&amp;CK Technique | <ul></ul>                             |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              |  There is no Trigger for this technique yet.  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>Unknown</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Suspicious TSCON Start
status: experimental
description: Detects a tscon.exe start as LOCAL SYSTEM 
reference: 
    - http://www.korznikov.com/2017/03/0-day-or-feature-privilege-escalation.html
    - https://medium.com/@networksecurity/rdp-hijacking-how-to-hijack-rds-and-remoteapp-sessions-transparently-to-move-through-an-da2a1e73a5f6
author: Florian Roth
date: 2018/03/17
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1
        User: 'NT AUTHORITY\SYSTEM'
        Image: '*\tscon.exe'
    condition: selection
falsepositives:
    - Unknown
level: high

```





### es-qs
    
```
(EventID:"1" AND User:"NT\\ AUTHORITY\\\\SYSTEM" AND Image.keyword:*\\\\tscon.exe)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Suspicious-TSCON-Start <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"1\\" AND User:\\"NT\\\\ AUTHORITY\\\\\\\\SYSTEM\\" AND Image.keyword:*\\\\\\\\tscon.exe)",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Suspicious TSCON Start\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"1" AND User:"NT AUTHORITY\\\\SYSTEM" AND Image:"*\\\\tscon.exe")
```


### splunk
    
```
(EventID="1" User="NT AUTHORITY\\\\SYSTEM" Image="*\\\\tscon.exe")
```


### logpoint
    
```
(EventID="1" User="NT AUTHORITY\\\\SYSTEM" Image="*\\\\tscon.exe")
```


### grep
    
```
grep -P '^(?:.*(?=.*1)(?=.*NT AUTHORITY\\SYSTEM)(?=.*.*\\tscon\\.exe))'
```



