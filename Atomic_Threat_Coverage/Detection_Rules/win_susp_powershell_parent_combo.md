| Title                | Suspicious PowerShell Invocation based on Parent Process                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious powershell invocations from interpreters or unusual programs                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Microsoft Operations Manager (MOM)</li><li>Other scripts</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://www.carbonblack.com/2017/03/15/attackers-leverage-excel-powershell-dns-latest-non-malware-attack/](https://www.carbonblack.com/2017/03/15/attackers-leverage-excel-powershell-dns-latest-non-malware-attack/)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Suspicious PowerShell Invocation based on Parent Process
status: experimental
description: Detects suspicious powershell invocations from interpreters or unusual programs
author: Florian Roth
references:
    - https://www.carbonblack.com/2017/03/15/attackers-leverage-excel-powershell-dns-latest-non-malware-attack/
tags:
    - attack.execution
    - attack.t1086
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage:
            - '*\wscript.exe'
            - '*\cscript.exe'
        Image:
            - '*\powershell.exe'
    falsepositive:
        CurrentDirectory: '*\Health Service State\\*'
    condition: selection and not falsepositive
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Microsoft Operations Manager (MOM)
    - Other scripts
level: medium

```





### es-qs
    
```
((ParentImage.keyword:(*\\\\wscript.exe *\\\\cscript.exe) AND Image.keyword:(*\\\\powershell.exe)) AND (NOT (CurrentDirectory.keyword:*\\\\Health\\ Service\\ State\\\\*)))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Suspicious-PowerShell-Invocation-based-on-Parent-Process <<EOF\n{\n  "metadata": {\n    "title": "Suspicious PowerShell Invocation based on Parent Process",\n    "description": "Detects suspicious powershell invocations from interpreters or unusual programs",\n    "tags": [\n      "attack.execution",\n      "attack.t1086"\n    ],\n    "query": "((ParentImage.keyword:(*\\\\\\\\wscript.exe *\\\\\\\\cscript.exe) AND Image.keyword:(*\\\\\\\\powershell.exe)) AND (NOT (CurrentDirectory.keyword:*\\\\\\\\Health\\\\ Service\\\\ State\\\\\\\\*)))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((ParentImage.keyword:(*\\\\\\\\wscript.exe *\\\\\\\\cscript.exe) AND Image.keyword:(*\\\\\\\\powershell.exe)) AND (NOT (CurrentDirectory.keyword:*\\\\\\\\Health\\\\ Service\\\\ State\\\\\\\\*)))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Suspicious PowerShell Invocation based on Parent Process\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((ParentImage:("*\\\\wscript.exe" "*\\\\cscript.exe") AND Image:("*\\\\powershell.exe")) AND NOT (CurrentDirectory:"*\\\\Health Service State\\\\*"))
```


### splunk
    
```
(((ParentImage="*\\\\wscript.exe" OR ParentImage="*\\\\cscript.exe") (Image="*\\\\powershell.exe")) NOT (CurrentDirectory="*\\\\Health Service State\\\\*")) | table CommandLine,ParentCommandLine
```


### logpoint
    
```
((ParentImage IN ["*\\\\wscript.exe", "*\\\\cscript.exe"] Image IN ["*\\\\powershell.exe"])  -(CurrentDirectory="*\\\\Health Service State\\\\*"))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*(?:.*.*\\wscript\\.exe|.*.*\\cscript\\.exe))(?=.*(?:.*.*\\powershell\\.exe))))(?=.*(?!.*(?:.*(?=.*.*\\Health Service State\\\\.*)))))'
```



