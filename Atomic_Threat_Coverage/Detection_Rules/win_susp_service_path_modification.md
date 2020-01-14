| Title                | Suspicious service path modification                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects service path modification to powershell/cmd                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1031: Modify Existing Service](https://attack.mitre.org/techniques/T1031)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1031: Modify Existing Service](../Triggers/T1031.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1031/T1031.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1031/T1031.yaml)</li></ul>  |
| Author               | Victor Sergeev, oscd.community |


## Detection Rules

### Sigma rule

```
title: Suspicious service path modification
id: 138d3531-8793-4f50-a2cd-f291b2863d78
description: Detects service path modification to powershell/cmd
status: experimental
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1031/T1031.yaml
tags:
    - attack.persistence
    - attack.t1031
date: 2019/10/21
modified: 2019/11/10
author: Victor Sergeev, oscd.community
logsource:
    category: process_creation
    product: windows
detection:
    selection_1:
        Image|endswith: '\sc.exe'
        CommandLine|contains|all:
            - 'config'
            - 'binpath'
    selection_2:
        CommandLine|contains:
            - 'powershell'
            - 'cmd'
    condition: selection_1 and selection_2
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Unknown
level: high

```





### es-qs
    
```
(Image.keyword:*\\\\sc.exe AND CommandLine.keyword:*config* AND CommandLine.keyword:*binpath* AND CommandLine.keyword:(*powershell* OR *cmd*))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Suspicious-service-path-modification <<EOF\n{\n  "metadata": {\n    "title": "Suspicious service path modification",\n    "description": "Detects service path modification to powershell/cmd",\n    "tags": [\n      "attack.persistence",\n      "attack.t1031"\n    ],\n    "query": "(Image.keyword:*\\\\\\\\sc.exe AND CommandLine.keyword:*config* AND CommandLine.keyword:*binpath* AND CommandLine.keyword:(*powershell* OR *cmd*))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(Image.keyword:*\\\\\\\\sc.exe AND CommandLine.keyword:*config* AND CommandLine.keyword:*binpath* AND CommandLine.keyword:(*powershell* OR *cmd*))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Suspicious service path modification\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(Image.keyword:*\\\\sc.exe AND CommandLine.keyword:*config* AND CommandLine.keyword:*binpath* AND CommandLine.keyword:(*powershell* *cmd*))
```


### splunk
    
```
(Image="*\\\\sc.exe" CommandLine="*config*" CommandLine="*binpath*" (CommandLine="*powershell*" OR CommandLine="*cmd*")) | table CommandLine,ParentCommandLine
```


### logpoint
    
```
(event_id="1" Image="*\\\\sc.exe" CommandLine="*config*" CommandLine="*binpath*" CommandLine IN ["*powershell*", "*cmd*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\\sc\\.exe)(?=.*.*config.*)(?=.*.*binpath.*)(?=.*(?:.*.*powershell.*|.*.*cmd.*)))'
```



