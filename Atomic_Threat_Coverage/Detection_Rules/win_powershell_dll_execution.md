| Title                | Detection of PowerShell Execution via DLL                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects PowerShell Strings applied to rundllas seen in PowerShdll.dll                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/p3nt4/PowerShdll/blob/master/README.md](https://github.com/p3nt4/PowerShdll/blob/master/README.md)</li></ul>  |
| Author               | Markus Neis |
| Other Tags           | <ul><li>car.2014-04-003</li><li>car.2014-04-003</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Detection of PowerShell Execution via DLL
status: experimental
description: Detects PowerShell Strings applied to rundllas seen in PowerShdll.dll
references:
    - https://github.com/p3nt4/PowerShdll/blob/master/README.md
tags:
    - attack.execution
    - attack.t1086
    - car.2014-04-003
author: Markus Neis
date: 2018/08/25
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        Image:
            - '*\rundll32.exe'
    selection2:
        Description:
            - '*Windows-Hostprozess (Rundll32)*'
    selection3:
        CommandLine:
            - '*Default.GetString*'
            - '*FromBase64String*'
    condition: (selection1 or selection2) and selection3
falsepositives:
    - Unknown
level: high

```





### es-qs
    
```
((Image.keyword:(*\\\\rundll32.exe) OR Description.keyword:(*Windows\\-Hostprozess\\ \\(Rundll32\\)*)) AND CommandLine.keyword:(*Default.GetString* *FromBase64String*))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Detection-of-PowerShell-Execution-via-DLL <<EOF\n{\n  "metadata": {\n    "title": "Detection of PowerShell Execution via DLL",\n    "description": "Detects PowerShell Strings applied to rundllas seen in PowerShdll.dll",\n    "tags": [\n      "attack.execution",\n      "attack.t1086",\n      "car.2014-04-003"\n    ],\n    "query": "((Image.keyword:(*\\\\\\\\rundll32.exe) OR Description.keyword:(*Windows\\\\-Hostprozess\\\\ \\\\(Rundll32\\\\)*)) AND CommandLine.keyword:(*Default.GetString* *FromBase64String*))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((Image.keyword:(*\\\\\\\\rundll32.exe) OR Description.keyword:(*Windows\\\\-Hostprozess\\\\ \\\\(Rundll32\\\\)*)) AND CommandLine.keyword:(*Default.GetString* *FromBase64String*))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Detection of PowerShell Execution via DLL\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((Image:("*\\\\rundll32.exe") OR Description:("*Windows\\-Hostprozess \\(Rundll32\\)*")) AND CommandLine:("*Default.GetString*" "*FromBase64String*"))
```


### splunk
    
```
(((Image="*\\\\rundll32.exe") OR (Description="*Windows-Hostprozess (Rundll32)*")) (CommandLine="*Default.GetString*" OR CommandLine="*FromBase64String*"))
```


### logpoint
    
```
((Image IN ["*\\\\rundll32.exe"] OR Description IN ["*Windows-Hostprozess (Rundll32)*"]) CommandLine IN ["*Default.GetString*", "*FromBase64String*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?:.*(?:.*.*\\rundll32\\.exe)|.*(?:.*.*Windows-Hostprozess \\(Rundll32\\).*))))(?=.*(?:.*.*Default\\.GetString.*|.*.*FromBase64String.*)))'
```



