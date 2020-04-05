| Title                    | Indirect Command Execution       |
|:-------------------------|:------------------|
| **Description**          | Detect indirect command execution via Program Compatibility Assistant pcalua.exe or forfiles.exe |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1202: Indirect Command Execution](https://attack.mitre.org/techniques/T1202)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1202: Indirect Command Execution](../Triggers/T1202.md)</li></ul>  |
| **Severity Level**       | low |
| **False Positives**      | <ul><li>Need to use extra processing with 'unique_count' / 'filter' to focus on outliers as opposed to commonly seen artifacts</li><li>Legit usage of scripts</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1202/T1202.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1202/T1202.yaml)</li><li>[https://eqllib.readthedocs.io/en/latest/analytics/884a7ccd-7305-4130-82d0-d4f90bc118b6.html](https://eqllib.readthedocs.io/en/latest/analytics/884a7ccd-7305-4130-82d0-d4f90bc118b6.html)</li></ul>  |
| **Author**               | E.M. Anhaus (orignally from Atomic Blue Detections, Endgame), oscd.community |


## Detection Rules

### Sigma rule

```
title: Indirect Command Execution
id: fa47597e-90e9-41cd-ab72-c3b74cfb0d02
description: Detect indirect command execution via Program Compatibility Assistant pcalua.exe or forfiles.exe
status: experimental
author: E.M. Anhaus (orignally from Atomic Blue Detections, Endgame), oscd.community
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1202/T1202.yaml
    - https://eqllib.readthedocs.io/en/latest/analytics/884a7ccd-7305-4130-82d0-d4f90bc118b6.html
date: 2019/10/24
modified: 2019/11/11
tags:
    - attack.defense_evasion
    - attack.t1202
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith:
            - '\pcalua.exe'
            - '\forfiles.exe'
    condition: selection
fields:
    - ComputerName
    - User
    - ParentCommandLine
    - CommandLine
falsepositives:
    - Need to use extra processing with 'unique_count' / 'filter' to focus on outliers as opposed to commonly seen artifacts
    - Legit usage of scripts
level: low

```





### es-qs
    
```
ParentImage.keyword:(*\\\\pcalua.exe OR *\\\\forfiles.exe)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/fa47597e-90e9-41cd-ab72-c3b74cfb0d02 <<EOF\n{\n  "metadata": {\n    "title": "Indirect Command Execution",\n    "description": "Detect indirect command execution via Program Compatibility Assistant pcalua.exe or forfiles.exe",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1202"\n    ],\n    "query": "ParentImage.keyword:(*\\\\\\\\pcalua.exe OR *\\\\\\\\forfiles.exe)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "ParentImage.keyword:(*\\\\\\\\pcalua.exe OR *\\\\\\\\forfiles.exe)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Indirect Command Execution\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n     ComputerName = {{_source.ComputerName}}\\n             User = {{_source.User}}\\nParentCommandLine = {{_source.ParentCommandLine}}\\n      CommandLine = {{_source.CommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
ParentImage.keyword:(*\\\\pcalua.exe *\\\\forfiles.exe)
```


### splunk
    
```
(ParentImage="*\\\\pcalua.exe" OR ParentImage="*\\\\forfiles.exe") | table ComputerName,User,ParentCommandLine,CommandLine
```


### logpoint
    
```
(event_id="1" ParentImage IN ["*\\\\pcalua.exe", "*\\\\forfiles.exe"])
```


### grep
    
```
grep -P '^(?:.*.*\\pcalua\\.exe|.*.*\\forfiles\\.exe)'
```



