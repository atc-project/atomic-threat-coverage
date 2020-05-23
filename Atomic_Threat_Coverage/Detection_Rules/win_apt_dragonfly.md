| Title                    | CrackMapExecWin       |
|:-------------------------|:------------------|
| **Description**          | Detects CrackMapExecWin Activity as Described by NCSC |
| **ATT&amp;CK Tactic**    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| **ATT&amp;CK Technique** |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| **Data Needed**          | <ul><li>[DN_0001_4688_windows_process_creation](../Data_Needed/DN_0001_4688_windows_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>None</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control](https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control)</li></ul>  |
| **Author**               | Markus Neis |
| Other Tags           | <ul><li>attack.g0035</li></ul> | 

## Detection Rules

### Sigma rule

```
title: CrackMapExecWin
id: 04d9079e-3905-4b70-ad37-6bdf11304965
description: Detects CrackMapExecWin Activity as Described by NCSC
status: experimental
references:
    - https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control
tags:
    - attack.g0035
author: Markus Neis
date: 2018/04/08
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image:
            - '*\crackmapexec.exe'
    condition: selection
falsepositives:
    - None
level: critical

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "Image.*.*\\\\crackmapexec.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.Image.keyword:(*\\\\crackmapexec.exe)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/04d9079e-3905-4b70-ad37-6bdf11304965 <<EOF\n{\n  "metadata": {\n    "title": "CrackMapExecWin",\n    "description": "Detects CrackMapExecWin Activity as Described by NCSC",\n    "tags": [\n      "attack.g0035"\n    ],\n    "query": "winlog.event_data.Image.keyword:(*\\\\\\\\crackmapexec.exe)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "winlog.event_data.Image.keyword:(*\\\\\\\\crackmapexec.exe)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'CrackMapExecWin\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
Image.keyword:(*\\\\crackmapexec.exe)
```


### splunk
    
```
(Image="*\\\\crackmapexec.exe")
```


### logpoint
    
```
Image IN ["*\\\\crackmapexec.exe"]
```


### grep
    
```
grep -P '^(?:.*.*\\crackmapexec\\.exe)'
```



