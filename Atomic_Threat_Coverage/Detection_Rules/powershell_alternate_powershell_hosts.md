| Title                | Alternate PowerShell Hosts                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects alternate PowerShell hosts potentially bypassing detections looking for powershell.exe                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| Data Needed          | <ul><li>[DN_0037_4103_windows_powershell_executing_pipeline](../Data_Needed/DN_0037_4103_windows_powershell_executing_pipeline.md)</li></ul>  |
| Trigger              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Programs using PowerShell directly without invocation of a dedicated interpreter</li><li>MSP Detection Searcher</li><li>Citrix ConfigSync.ps1</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/02_execution/T1086_powershell/alternate_signed_powershell_hosts.md](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/02_execution/T1086_powershell/alternate_signed_powershell_hosts.md)</li></ul>  |
| Author               | Roberto Rodriguez @Cyb3rWard0g |


## Detection Rules

### Sigma rule

```
title: Alternate PowerShell Hosts
id: 64e8e417-c19a-475a-8d19-98ea705394cc
description: Detects alternate PowerShell hosts potentially bypassing detections looking for powershell.exe
status: experimental
date: 2019/08/11
modified: 2020/02/25
author: Roberto Rodriguez @Cyb3rWard0g
references:
    - https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/02_execution/T1086_powershell/alternate_signed_powershell_hosts.md
tags:
    - attack.execution
    - attack.t1086
logsource:
    product: windows
    service: powershell
detection:
    selection: 
        EventID:
            - 4103
            - 400
        ContextInfo: '*'
    filter:
        - ContextInfo: 'powershell.exe'
        - Message: 'powershell.exe'
        # Both fields contain key=value pairs where the key HostApplication ist relevant but
        # can't be referred directly as event field.
    condition: selection and not filter
falsepositives:
    - Programs using PowerShell directly without invocation of a dedicated interpreter
    - MSP Detection Searcher
    - Citrix ConfigSync.ps1
level: medium

```





### es-qs
    
```
((EventID:("4103" OR "400") AND ContextInfo.keyword:*) AND (NOT (ContextInfo:"powershell.exe" OR Message:"powershell.exe")))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/64e8e417-c19a-475a-8d19-98ea705394cc <<EOF\n{\n  "metadata": {\n    "title": "Alternate PowerShell Hosts",\n    "description": "Detects alternate PowerShell hosts potentially bypassing detections looking for powershell.exe",\n    "tags": [\n      "attack.execution",\n      "attack.t1086"\n    ],\n    "query": "((EventID:(\\"4103\\" OR \\"400\\") AND ContextInfo.keyword:*) AND (NOT (ContextInfo:\\"powershell.exe\\" OR Message:\\"powershell.exe\\")))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((EventID:(\\"4103\\" OR \\"400\\") AND ContextInfo.keyword:*) AND (NOT (ContextInfo:\\"powershell.exe\\" OR Message:\\"powershell.exe\\")))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Alternate PowerShell Hosts\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((EventID:("4103" "400") AND ContextInfo.keyword:*) AND (NOT (ContextInfo:"powershell.exe" OR Message:"powershell.exe")))
```


### splunk
    
```
(((EventID="4103" OR EventID="400") ContextInfo="*") NOT (ContextInfo="powershell.exe" OR Message="powershell.exe"))
```


### logpoint
    
```
((event_id IN ["4103", "400"] ContextInfo="*")  -(ContextInfo="powershell.exe" OR Message="powershell.exe"))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*(?:.*4103|.*400))(?=.*.*)))(?=.*(?!.*(?:.*(?:.*(?=.*powershell\\.exe)|.*(?=.*powershell\\.exe))))))'
```



