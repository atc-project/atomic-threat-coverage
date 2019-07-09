| Title                | WMI Spawning Windows PowerShell                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects WMI spawning PowerShell                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1064: Scripting](https://attack.mitre.org/techniques/T1064)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1064: Scripting](../Triggers/T1064.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>AppvClient</li><li>CCM</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/Neo23x0/sigma/blob/master/rules/windows/process_creation/win_shell_spawn_susp_program.yml](https://github.com/Neo23x0/sigma/blob/master/rules/windows/process_creation/win_shell_spawn_susp_program.yml)</li><li>[https://any.run/report/68bc255f9b0db6a0d30a8f2dadfbee3256acfe12497bf93943bc1eab0735e45e/a2385d6f-34f7-403c-90d3-b1f9d2a90a5e](https://any.run/report/68bc255f9b0db6a0d30a8f2dadfbee3256acfe12497bf93943bc1eab0735e45e/a2385d6f-34f7-403c-90d3-b1f9d2a90a5e)</li></ul>  |
| Author               | Markus Neis / @Karneades |


## Detection Rules

### Sigma rule

```
title: WMI Spawning Windows PowerShell
status: experimental
description: Detects WMI spawning PowerShell 
references:
    - https://github.com/Neo23x0/sigma/blob/master/rules/windows/process_creation/win_shell_spawn_susp_program.yml
    - https://any.run/report/68bc255f9b0db6a0d30a8f2dadfbee3256acfe12497bf93943bc1eab0735e45e/a2385d6f-34f7-403c-90d3-b1f9d2a90a5e
author: Markus Neis / @Karneades
date: 2019/04/03
tags:
    - attack.execution
    - attack.defense_evasion
    - attack.t1064
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage:
            - '*\wmiprvse.exe'
        Image:
            - '*\powershell.exe'
    condition: selection
falsepositives:
    - AppvClient
    - CCM
level: high

```





### es-qs
    
```
(ParentImage.keyword:(*\\\\wmiprvse.exe) AND Image.keyword:(*\\\\powershell.exe))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/WMI-Spawning-Windows-PowerShell <<EOF\n{\n  "metadata": {\n    "title": "WMI Spawning Windows PowerShell",\n    "description": "Detects WMI spawning PowerShell",\n    "tags": [\n      "attack.execution",\n      "attack.defense_evasion",\n      "attack.t1064"\n    ],\n    "query": "(ParentImage.keyword:(*\\\\\\\\wmiprvse.exe) AND Image.keyword:(*\\\\\\\\powershell.exe))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(ParentImage.keyword:(*\\\\\\\\wmiprvse.exe) AND Image.keyword:(*\\\\\\\\powershell.exe))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'WMI Spawning Windows PowerShell\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(ParentImage:("*\\\\wmiprvse.exe") AND Image:("*\\\\powershell.exe"))
```


### splunk
    
```
((ParentImage="*\\\\wmiprvse.exe") (Image="*\\\\powershell.exe"))
```


### logpoint
    
```
(ParentImage IN ["*\\\\wmiprvse.exe"] Image IN ["*\\\\powershell.exe"])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*\\wmiprvse\\.exe))(?=.*(?:.*.*\\powershell\\.exe)))'
```



