| Title                    | BlueMashroom DLL Load       |
|:-------------------------|:------------------|
| **Description**          | Detects a suspicious DLL loading from AppData Local path as described in BlueMashroom report |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1117: Regsvr32](https://attack.mitre.org/techniques/T1117)</li><li>[T1218.010: Regsvr32](https://attack.mitre.org/techniques/T1218/010)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1218.010: Regsvr32](../Triggers/T1218.010.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Unlikely</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.virusbulletin.com/conference/vb2019/abstracts/apt-cases-exploiting-vulnerabilities-region-specific-software](https://www.virusbulletin.com/conference/vb2019/abstracts/apt-cases-exploiting-vulnerabilities-region-specific-software)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: BlueMashroom DLL Load
id: bd70d3f8-e60e-4d25-89f0-0b5a9cff20e0
status: experimental
description: Detects a suspicious DLL loading from AppData Local path as described in BlueMashroom report
references:
    - https://www.virusbulletin.com/conference/vb2019/abstracts/apt-cases-exploiting-vulnerabilities-region-specific-software
tags:
    - attack.defense_evasion
    - attack.t1117 # an old one
    - attack.t1218.010
author: Florian Roth
date: 2019/10/02
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - '*\regsvr32*\AppData\Local\\*'
            - '*\AppData\Local\\*,DllEntry*'
    condition: selection
falsepositives:
    - Unlikely
level: critical

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "CommandLine.*.*\\\\regsvr32.*\\\\AppData\\\\Local\\\\.*" -or $_.message -match "CommandLine.*.*\\\\AppData\\\\Local\\\\.*,DllEntry.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.CommandLine.keyword:(*\\\\regsvr32*\\\\AppData\\\\Local\\\\* OR *\\\\AppData\\\\Local\\\\*,DllEntry*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/bd70d3f8-e60e-4d25-89f0-0b5a9cff20e0 <<EOF\n{\n  "metadata": {\n    "title": "BlueMashroom DLL Load",\n    "description": "Detects a suspicious DLL loading from AppData Local path as described in BlueMashroom report",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1117",\n      "attack.t1218.010"\n    ],\n    "query": "winlog.event_data.CommandLine.keyword:(*\\\\\\\\regsvr32*\\\\\\\\AppData\\\\\\\\Local\\\\\\\\* OR *\\\\\\\\AppData\\\\\\\\Local\\\\\\\\*,DllEntry*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "winlog.event_data.CommandLine.keyword:(*\\\\\\\\regsvr32*\\\\\\\\AppData\\\\\\\\Local\\\\\\\\* OR *\\\\\\\\AppData\\\\\\\\Local\\\\\\\\*,DllEntry*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'BlueMashroom DLL Load\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
CommandLine.keyword:(*\\\\regsvr32*\\\\AppData\\\\Local\\\\* *\\\\AppData\\\\Local\\\\*,DllEntry*)
```


### splunk
    
```
(CommandLine="*\\\\regsvr32*\\\\AppData\\\\Local\\\\*" OR CommandLine="*\\\\AppData\\\\Local\\\\*,DllEntry*")
```


### logpoint
    
```
CommandLine IN ["*\\\\regsvr32*\\\\AppData\\\\Local\\\\*", "*\\\\AppData\\\\Local\\\\*,DllEntry*"]
```


### grep
    
```
grep -P '^(?:.*.*\\regsvr32.*\\AppData\\Local\\\\.*|.*.*\\AppData\\Local\\\\.*,DllEntry.*)'
```



