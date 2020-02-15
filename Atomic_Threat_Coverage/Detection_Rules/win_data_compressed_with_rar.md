| Title                | Data Compressed                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | An adversary may compress data (e.g., sensitive documents) that is collected prior to exfiltration in order to make it portable and minimize the amount of data sent over the network                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0010: Exfiltration](https://attack.mitre.org/tactics/TA0010)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1002: Data Compressed](https://attack.mitre.org/techniques/T1002)</li></ul>  |
| Data Needed          |  There is no documented Data Needed for this Detection Rule yet  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1002: Data Compressed](../Triggers/T1002.md)</li></ul>  |
| Severity Level       | low |
| False Positives      | <ul><li>highly likely if rar is default archiver in the monitored environment</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1002/T1002.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1002/T1002.yaml)</li></ul>  |
| Author               | Timur Zinniatullin, oscd.community |


## Detection Rules

### Sigma rule

```
title: Data Compressed
id: 6f3e2987-db24-4c78-a860-b4f4095a7095
status: experimental
description: An adversary may compress data (e.g., sensitive documents) that is collected prior to exfiltration in order to make it portable and minimize the amount
    of data sent over the network
author: Timur Zinniatullin, oscd.community
date: 2019/10/21
modified: 2019/11/04
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1002/T1002.yaml
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\rar.exe'
        CommandLine|contains|all:
            - ' a '
            - '-r'
    condition: selection
fields:
    - Image
    - CommandLine
    - User
    - LogonGuid
    - Hashes
    - ParentProcessGuid
    - ParentCommandLine
falsepositives:
    - highly likely if rar is default archiver in the monitored environment
level: low
tags:
    - attack.exfiltration
    - attack.t1002

```





### es-qs
    
```
(Image.keyword:*\\\\rar.exe AND CommandLine.keyword:*\\ a\\ * AND CommandLine.keyword:*\\-r*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Data-Compressed <<EOF\n{\n  "metadata": {\n    "title": "Data Compressed",\n    "description": "An adversary may compress data (e.g., sensitive documents) that is collected prior to exfiltration in order to make it portable and minimize the amount of data sent over the network",\n    "tags": [\n      "attack.exfiltration",\n      "attack.t1002"\n    ],\n    "query": "(Image.keyword:*\\\\\\\\rar.exe AND CommandLine.keyword:*\\\\ a\\\\ * AND CommandLine.keyword:*\\\\-r*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(Image.keyword:*\\\\\\\\rar.exe AND CommandLine.keyword:*\\\\ a\\\\ * AND CommandLine.keyword:*\\\\-r*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Data Compressed\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n            Image = {{_source.Image}}\\n      CommandLine = {{_source.CommandLine}}\\n             User = {{_source.User}}\\n        LogonGuid = {{_source.LogonGuid}}\\n           Hashes = {{_source.Hashes}}\\nParentProcessGuid = {{_source.ParentProcessGuid}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(Image.keyword:*\\\\rar.exe AND CommandLine.keyword:* a * AND CommandLine.keyword:*\\-r*)
```


### splunk
    
```
(Image="*\\\\rar.exe" CommandLine="* a *" CommandLine="*-r*") | table Image,CommandLine,User,LogonGuid,Hashes,ParentProcessGuid,ParentCommandLine
```


### logpoint
    
```
(event_id="1" Image="*\\\\rar.exe" CommandLine="* a *" CommandLine="*-r*")
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\\rar\\.exe)(?=.*.* a .*)(?=.*.*-r.*))'
```



