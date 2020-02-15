| Title                | T1086 Alternate PowerShell Hosts                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects alternate PowerShell hosts potentially bypassing detections looking for powershell.exe                                                                                                                                           |
| ATT&amp;CK Tactic    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| ATT&amp;CK Technique |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| Data Needed          | <ul><li>[DN_0020_17_windows_sysmon_PipeEvent](../Data_Needed/DN_0020_17_windows_sysmon_PipeEvent.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              |  There is no documented Trigger for this Detection Rule yet  |
| Severity Level       | critical |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/02_execution/T1086_powershell/alternate_signed_powershell_hosts.md](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/02_execution/T1086_powershell/alternate_signed_powershell_hosts.md)</li></ul>  |
| Author               | Roberto Rodriguez @Cyb3rWard0g |


## Detection Rules

### Sigma rule

```
title: T1086 Alternate PowerShell Hosts
id: 58cb02d5-78ce-4692-b3e1-dce850aae41a
description: Detects alternate PowerShell hosts potentially bypassing detections looking for powershell.exe
status: experimental
date: 2019/09/12
modified: 2019/11/10
author: Roberto Rodriguez @Cyb3rWard0g
references:
    - https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/02_execution/T1086_powershell/alternate_signed_powershell_hosts.md
logsource:
    product: windows
    service: sysmon
detection:
    selection: 
        EventID: 17
        PipeName|startswith: '\PSHost'
    filter:
        Image|startswith: '\powershell.exe'
    condition: selection and not filter
falsepositives:
    - Unknown
level: critical
```





### es-qs
    
```
((EventID:"17" AND PipeName.keyword:\\\\PSHost*) AND (NOT (Image.keyword:\\\\powershell.exe*)))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/T1086-Alternate-PowerShell-Hosts <<EOF\n{\n  "metadata": {\n    "title": "T1086 Alternate PowerShell Hosts",\n    "description": "Detects alternate PowerShell hosts potentially bypassing detections looking for powershell.exe",\n    "tags": "",\n    "query": "((EventID:\\"17\\" AND PipeName.keyword:\\\\\\\\PSHost*) AND (NOT (Image.keyword:\\\\\\\\powershell.exe*)))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((EventID:\\"17\\" AND PipeName.keyword:\\\\\\\\PSHost*) AND (NOT (Image.keyword:\\\\\\\\powershell.exe*)))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'T1086 Alternate PowerShell Hosts\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((EventID:"17" AND PipeName.keyword:\\\\PSHost*) AND (NOT (Image.keyword:\\\\powershell.exe*)))
```


### splunk
    
```
((EventID="17" PipeName="\\\\PSHost*") NOT (Image="\\\\powershell.exe*"))
```


### logpoint
    
```
((event_id="17" PipeName="\\\\PSHost*")  -(Image="\\\\powershell.exe*"))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*17)(?=.*\\PSHost.*)))(?=.*(?!.*(?:.*(?=.*\\powershell\\.exe.*)))))'
```



