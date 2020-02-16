| Title                | Stop windows service                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a windows service to be stopped                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0040: Impact](https://attack.mitre.org/tactics/TA0040)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1489: Service Stop](https://attack.mitre.org/techniques/T1489)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Trigger              | <ul><li>[T1489: Service Stop](../Triggers/T1489.md)</li></ul>  |
| Severity Level       | low |
| False Positives      | <ul><li>Administrator shutting down the service due to upgrade or removal purposes</li></ul>  |
| Development Status   | experimental |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Jakob Weinzettl, oscd.community |


## Detection Rules

### Sigma rule

```
title: Stop windows service
id: eb87818d-db5d-49cc-a987-d5da331fbd90
description: Detects a windows service to be stopped
status: experimental
author: Jakob Weinzettl, oscd.community
date: 2019/10/23
modified: 2019/11/08
tags:
    - attack.impact
    - attack.t1489
detection:
    selection:
      - Image|endswith: '\taskkill.exe'
      - Image|endswith:
            - '\sc.exe'
            - '\net.exe'
            - '\net1.exe'
        CommandLine|contains: 'stop'
    condition: selection
falsepositives:
    - Administrator shutting down the service due to upgrade or removal purposes
level: low
logsource:
    category: process_creation
    product: windows

```





### es-qs
    
```
(Image.keyword:*\\\\taskkill.exe OR (Image.keyword:(*\\\\sc.exe OR *\\\\net.exe OR *\\\\net1.exe) AND CommandLine.keyword:*stop*))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Stop-windows-service <<EOF\n{\n  "metadata": {\n    "title": "Stop windows service",\n    "description": "Detects a windows service to be stopped",\n    "tags": [\n      "attack.impact",\n      "attack.t1489"\n    ],\n    "query": "(Image.keyword:*\\\\\\\\taskkill.exe OR (Image.keyword:(*\\\\\\\\sc.exe OR *\\\\\\\\net.exe OR *\\\\\\\\net1.exe) AND CommandLine.keyword:*stop*))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(Image.keyword:*\\\\\\\\taskkill.exe OR (Image.keyword:(*\\\\\\\\sc.exe OR *\\\\\\\\net.exe OR *\\\\\\\\net1.exe) AND CommandLine.keyword:*stop*))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Stop windows service\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(Image.keyword:*\\\\taskkill.exe OR (Image.keyword:(*\\\\sc.exe *\\\\net.exe *\\\\net1.exe) AND CommandLine.keyword:*stop*))
```


### splunk
    
```
(Image="*\\\\taskkill.exe" OR ((Image="*\\\\sc.exe" OR Image="*\\\\net.exe" OR Image="*\\\\net1.exe") CommandLine="*stop*"))
```


### logpoint
    
```
(event_id="1" (Image="*\\\\taskkill.exe" OR (Image IN ["*\\\\sc.exe", "*\\\\net.exe", "*\\\\net1.exe"] CommandLine="*stop*")))
```


### grep
    
```
grep -P '^(?:.*(?:.*.*\\taskkill\\.exe|.*(?:.*(?=.*(?:.*.*\\sc\\.exe|.*.*\\net\\.exe|.*.*\\net1\\.exe))(?=.*.*stop.*))))'
```



