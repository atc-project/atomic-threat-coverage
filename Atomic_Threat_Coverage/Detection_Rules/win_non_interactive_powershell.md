| Title                | T1086 Non Interactive PowerShell                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects non-interactive PowerShell activity by looking at powershell.exe with not explorer.exe as a parent.                                                                                                                                           |
| ATT&amp;CK Tactic    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| ATT&amp;CK Technique |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              |  There is no documented Trigger for this Detection Rule yet  |
| Severity Level       | critical |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/02_execution/T1086_powershell/basic_powershell_execution.md](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/02_execution/T1086_powershell/basic_powershell_execution.md)</li></ul>  |
| Author               | Roberto Rodriguez @Cyb3rWard0g (rule), oscd.community (improvements) |


## Detection Rules

### Sigma rule

```
title: T1086 Non Interactive PowerShell
id: f4bbd493-b796-416e-bbf2-121235348529
description: Detects non-interactive PowerShell activity by looking at powershell.exe with not explorer.exe as a parent.
status: experimental
date: 2019/09/12
modified: 2019/11/10
author: Roberto Rodriguez @Cyb3rWard0g (rule), oscd.community (improvements)
references:
    - https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/02_execution/T1086_powershell/basic_powershell_execution.md
logsource:
    category: process_creation
    product: windows
detection:
    selection: 
        Image|endswith: '\powershell.exe'
    filter:
        ParentImage|endswith: '\explorer.exe'
    condition: selection and not filter
falsepositives:
    - Unknown
level: critical
```





### es-qs
    
```
(Image.keyword:*\\\\powershell.exe AND (NOT (ParentImage.keyword:*\\\\explorer.exe)))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/T1086-Non-Interactive-PowerShell <<EOF\n{\n  "metadata": {\n    "title": "T1086 Non Interactive PowerShell",\n    "description": "Detects non-interactive PowerShell activity by looking at powershell.exe with not explorer.exe as a parent.",\n    "tags": "",\n    "query": "(Image.keyword:*\\\\\\\\powershell.exe AND (NOT (ParentImage.keyword:*\\\\\\\\explorer.exe)))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(Image.keyword:*\\\\\\\\powershell.exe AND (NOT (ParentImage.keyword:*\\\\\\\\explorer.exe)))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'T1086 Non Interactive PowerShell\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(Image.keyword:*\\\\powershell.exe AND (NOT (ParentImage.keyword:*\\\\explorer.exe)))
```


### splunk
    
```
(Image="*\\\\powershell.exe" NOT (ParentImage="*\\\\explorer.exe"))
```


### logpoint
    
```
(event_id="1" Image="*\\\\powershell.exe"  -(ParentImage="*\\\\explorer.exe"))
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\\powershell\\.exe)(?=.*(?!.*(?:.*(?=.*.*\\explorer\\.exe)))))'
```



