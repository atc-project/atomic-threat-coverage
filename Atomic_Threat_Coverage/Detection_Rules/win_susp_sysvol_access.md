| Title                | Suspicious SYSVOL Domain Group Policy Access                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects Access to Domain Group Policies stored in SYSVOL                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1003: Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1003: Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>administrative activity</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://adsecurity.org/?p=2288](https://adsecurity.org/?p=2288)</li><li>[https://www.hybrid-analysis.com/sample/f2943f5e45befa52fb12748ca7171d30096e1d4fc3c365561497c618341299d5?environmentId=100](https://www.hybrid-analysis.com/sample/f2943f5e45befa52fb12748ca7171d30096e1d4fc3c365561497c618341299d5?environmentId=100)</li></ul>  |
| Author               | Markus Neis |


## Detection Rules

### Sigma rule

```
title: Suspicious SYSVOL Domain Group Policy Access
status: experimental
description: Detects Access to Domain Group Policies stored in SYSVOL
references:
    - https://adsecurity.org/?p=2288
    - https://www.hybrid-analysis.com/sample/f2943f5e45befa52fb12748ca7171d30096e1d4fc3c365561497c618341299d5?environmentId=100
author: Markus Neis
date: 2018/04/09
modified: 2018/12/11
tags:
    - attack.credential_access
    - attack.t1003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine: '*\SYSVOL\\*\policies\\*'
    condition: selection
falsepositives:
    - administrative activity
level: medium

```





### es-qs
    
```
CommandLine.keyword:*\\\\SYSVOL\\\\*\\\\policies\\\\*
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Suspicious-SYSVOL-Domain-Group-Policy-Access <<EOF\n{\n  "metadata": {\n    "title": "Suspicious SYSVOL Domain Group Policy Access",\n    "description": "Detects Access to Domain Group Policies stored in SYSVOL",\n    "tags": [\n      "attack.credential_access",\n      "attack.t1003"\n    ],\n    "query": "CommandLine.keyword:*\\\\\\\\SYSVOL\\\\\\\\*\\\\\\\\policies\\\\\\\\*"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "CommandLine.keyword:*\\\\\\\\SYSVOL\\\\\\\\*\\\\\\\\policies\\\\\\\\*",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Suspicious SYSVOL Domain Group Policy Access\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
CommandLine:"*\\\\SYSVOL\\\\*\\\\policies\\\\*"
```


### splunk
    
```
CommandLine="*\\\\SYSVOL\\\\*\\\\policies\\\\*"
```


### logpoint
    
```
CommandLine="*\\\\SYSVOL\\\\*\\\\policies\\\\*"
```


### grep
    
```
grep -P '^.*\\SYSVOL\\\\.*\\policies\\\\.*'
```



