| Title                | Invocation of Active Directory Diagnostic Tool (ntdsutil.exe)                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects execution of ntdsutil.exe, which can be used for various attacks against the NTDS database (NTDS.DIT)                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1003: Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1003: Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>NTDS maintenance</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://jpcertcc.github.io/ToolAnalysisResultSheet/details/ntdsutil.htm](https://jpcertcc.github.io/ToolAnalysisResultSheet/details/ntdsutil.htm)</li></ul>  |
| Author               | Thomas Patzke |


## Detection Rules

### Sigma rule

```
title: Invocation of Active Directory Diagnostic Tool (ntdsutil.exe)
description: Detects execution of ntdsutil.exe, which can be used for various attacks against the NTDS database (NTDS.DIT)
status: experimental
references:
    - https://jpcertcc.github.io/ToolAnalysisResultSheet/details/ntdsutil.htm
author: Thomas Patzke
tags:
    - attack.credential_access
    - attack.t1003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine: '*\ntdsutil*'
    condition: selection
falsepositives:
    - NTDS maintenance
level: high

```





### es-qs
    
```
CommandLine.keyword:*\\\\ntdsutil*
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Invocation-of-Active-Directory-Diagnostic-Tool-ntdsutil.exe <<EOF\n{\n  "metadata": {\n    "title": "Invocation of Active Directory Diagnostic Tool (ntdsutil.exe)",\n    "description": "Detects execution of ntdsutil.exe, which can be used for various attacks against the NTDS database (NTDS.DIT)",\n    "tags": [\n      "attack.credential_access",\n      "attack.t1003"\n    ],\n    "query": "CommandLine.keyword:*\\\\\\\\ntdsutil*"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "CommandLine.keyword:*\\\\\\\\ntdsutil*",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Invocation of Active Directory Diagnostic Tool (ntdsutil.exe)\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
CommandLine:"*\\\\ntdsutil*"
```


### splunk
    
```
CommandLine="*\\\\ntdsutil*"
```


### logpoint
    
```
CommandLine="*\\\\ntdsutil*"
```


### grep
    
```
grep -P '^.*\\ntdsutil.*'
```



