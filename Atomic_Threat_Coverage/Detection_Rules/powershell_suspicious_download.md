| Title                | Suspicious PowerShell Download                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious PowerShell download command                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| Data Needed          |  There is no documented Data Needed for this Detection Rule yet  |
| Trigger              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>PowerShell scripts that download content from the Internet</li></ul>  |
| Development Status   | experimental |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Suspicious PowerShell Download
id: 65531a81-a694-4e31-ae04-f8ba5bc33759
status: experimental
description: Detects suspicious PowerShell download command
tags:
    - attack.execution
    - attack.t1086
author: Florian Roth
logsource:
    product: windows
    service: powershell
detection:
    keywords:
        Message:
            - '*System.Net.WebClient).DownloadString(*'
            - '*system.net.webclient).downloadfile(*'
    condition: keywords
falsepositives:
    - PowerShell scripts that download content from the Internet
level: medium

```





### es-qs
    
```
Message.keyword:(*System.Net.WebClient\\).DownloadString\\(* OR *system.net.webclient\\).downloadfile\\(*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Suspicious-PowerShell-Download <<EOF\n{\n  "metadata": {\n    "title": "Suspicious PowerShell Download",\n    "description": "Detects suspicious PowerShell download command",\n    "tags": [\n      "attack.execution",\n      "attack.t1086"\n    ],\n    "query": "Message.keyword:(*System.Net.WebClient\\\\).DownloadString\\\\(* OR *system.net.webclient\\\\).downloadfile\\\\(*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "Message.keyword:(*System.Net.WebClient\\\\).DownloadString\\\\(* OR *system.net.webclient\\\\).downloadfile\\\\(*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Suspicious PowerShell Download\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
Message.keyword:(*System.Net.WebClient\\).DownloadString\\(* *system.net.webclient\\).downloadfile\\(*)
```


### splunk
    
```
(Message="*System.Net.WebClient).DownloadString(*" OR Message="*system.net.webclient).downloadfile(*")
```


### logpoint
    
```
Message IN ["*System.Net.WebClient).DownloadString(*", "*system.net.webclient).downloadfile(*"]
```


### grep
    
```
grep -P '^(?:.*.*System\\.Net\\.WebClient\\)\\.DownloadString\\(.*|.*.*system\\.net\\.webclient\\)\\.downloadfile\\(.*)'
```



