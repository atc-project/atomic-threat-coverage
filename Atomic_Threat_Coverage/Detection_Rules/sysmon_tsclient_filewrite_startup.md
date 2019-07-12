| Title                | Hijack legit RDP session to move laterally                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects the usage of tsclient share to place a backdoor on the RDP source machine's startup folder                                                                                                                                           |
| ATT&amp;CK Tactic    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| ATT&amp;CK Technique |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| Data Needed          | <ul><li>[DN_0015_11_windows_sysmon_FileCreate](../Data_Needed/DN_0015_11_windows_sysmon_FileCreate.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              |  There is no documented Trigger for this Detection Rule yet  |
| Severity Level       | high |
| False Positives      | <ul><li>unknown</li></ul>  |
| Development Status   | experimental |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Samir Bousseaden |


## Detection Rules

### Sigma rule

```
title: Hijack legit RDP session to move laterally  
status: experimental
description: Detects the usage of tsclient share to place a backdoor on the RDP source machine's startup folder
date: 2019/02/21
author: Samir Bousseaden
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 11
        Image: '*\mstsc.exe'
        TargetFileName: '*\Microsoft\Windows\Start Menu\Programs\Startup\*'
    condition: selection
falsepositives:
    - unknown
level: high

```





### es-qs
    
```
(EventID:"11" AND Image.keyword:*\\\\mstsc.exe AND TargetFileName.keyword:*\\\\Microsoft\\\\Windows\\\\Start\\ Menu\\\\Programs\\\\Startup\\*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Hijack-legit-RDP-session-to-move-laterally <<EOF\n{\n  "metadata": {\n    "title": "Hijack legit RDP session to move laterally",\n    "description": "Detects the usage of tsclient share to place a backdoor on the RDP source machine\'s startup folder",\n    "tags": "",\n    "query": "(EventID:\\"11\\" AND Image.keyword:*\\\\\\\\mstsc.exe AND TargetFileName.keyword:*\\\\\\\\Microsoft\\\\\\\\Windows\\\\\\\\Start\\\\ Menu\\\\\\\\Programs\\\\\\\\Startup\\\\*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"11\\" AND Image.keyword:*\\\\\\\\mstsc.exe AND TargetFileName.keyword:*\\\\\\\\Microsoft\\\\\\\\Windows\\\\\\\\Start\\\\ Menu\\\\\\\\Programs\\\\\\\\Startup\\\\*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Hijack legit RDP session to move laterally\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"11" AND Image:"*\\\\mstsc.exe" AND TargetFileName:"*\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\Startup\\*")
```


### splunk
    
```
(EventID="11" Image="*\\\\mstsc.exe" TargetFileName="*\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\Startup\\*")
```


### logpoint
    
```
(EventID="11" Image="*\\\\mstsc.exe" TargetFileName="*\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\Startup\\*")
```


### grep
    
```
grep -P '^(?:.*(?=.*11)(?=.*.*\\mstsc\\.exe)(?=.*.*\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\.*))'
```



