| Title                    | TAIDOOR RAT DLL Load       |
|:-------------------------|:------------------|
| **Description**          | Detects specific process characteristics of Chinese TAIDOOR RAT malware load |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1055: Process Injection](https://attack.mitre.org/techniques/T1055)</li><li>[T1055.001: Dynamic-link Library Injection](https://attack.mitre.org/techniques/T1055/001)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1055: Process Injection](../Triggers/T1055.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://us-cert.cisa.gov/ncas/analysis-reports/ar20-216a](https://us-cert.cisa.gov/ncas/analysis-reports/ar20-216a)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: TAIDOOR RAT DLL Load
id: d1aa3382-abab-446f-96ea-4de52908210b
status: experimental
description: Detects specific process characteristics of Chinese TAIDOOR RAT malware load
references:
    - https://us-cert.cisa.gov/ncas/analysis-reports/ar20-216a
author: Florian Roth
date: 2020/07/30
tags:
    - attack.execution
    - attack.t1055 # an old one
    - attack.t1055.001
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine|contains:
            - 'dll,MyStart'
            - 'dll MyStart'
    selection2a:
        CommandLine|endswith:
            - ' MyStart'
    selection2b:
        CommandLine|contains:
            - 'rundll32.exe' 
    condition: selection1 or ( selection2a and selection2b )
falsepositives:
    - Unknown
level: critical

```





### powershell
    
```
Get-WinEvent | where {(($_.message -match "CommandLine.*.*dll,MyStart.*" -or $_.message -match "CommandLine.*.*dll MyStart.*") -or (($_.message -match "CommandLine.*.* MyStart") -and ($_.message -match "CommandLine.*.*rundll32.exe.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.CommandLine.keyword:(*dll,MyStart* OR *dll\\ MyStart*) OR (winlog.event_data.CommandLine.keyword:(*\\ MyStart) AND winlog.event_data.CommandLine.keyword:(*rundll32.exe*)))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/d1aa3382-abab-446f-96ea-4de52908210b <<EOF\n{\n  "metadata": {\n    "title": "TAIDOOR RAT DLL Load",\n    "description": "Detects specific process characteristics of Chinese TAIDOOR RAT malware load",\n    "tags": [\n      "attack.execution",\n      "attack.t1055",\n      "attack.t1055.001"\n    ],\n    "query": "(winlog.event_data.CommandLine.keyword:(*dll,MyStart* OR *dll\\\\ MyStart*) OR (winlog.event_data.CommandLine.keyword:(*\\\\ MyStart) AND winlog.event_data.CommandLine.keyword:(*rundll32.exe*)))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.event_data.CommandLine.keyword:(*dll,MyStart* OR *dll\\\\ MyStart*) OR (winlog.event_data.CommandLine.keyword:(*\\\\ MyStart) AND winlog.event_data.CommandLine.keyword:(*rundll32.exe*)))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'TAIDOOR RAT DLL Load\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(CommandLine.keyword:(*dll,MyStart* *dll MyStart*) OR (CommandLine.keyword:(* MyStart) AND CommandLine.keyword:(*rundll32.exe*)))
```


### splunk
    
```
((CommandLine="*dll,MyStart*" OR CommandLine="*dll MyStart*") OR ((CommandLine="* MyStart") (CommandLine="*rundll32.exe*")))
```


### logpoint
    
```
(CommandLine IN ["*dll,MyStart*", "*dll MyStart*"] OR (CommandLine IN ["* MyStart"] CommandLine IN ["*rundll32.exe*"]))
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*.*dll,MyStart.*|.*.*dll MyStart.*)|.*(?:.*(?=.*(?:.*.* MyStart))(?=.*(?:.*.*rundll32\\.exe.*)))))'
```



