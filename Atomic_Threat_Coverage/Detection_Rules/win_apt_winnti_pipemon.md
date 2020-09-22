| Title                    | Winnti Pipemon Characteristics       |
|:-------------------------|:------------------|
| **Description**          | Detects specific process characteristics of Winnti Pipemon malware reported by ESET |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1574.002: DLL Side-Loading](https://attack.mitre.org/techniques/T1574.002)</li><li>[T1073: DLL Side-Loading](https://attack.mitre.org/techniques/T1073)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1574.002: DLL Side-Loading](../Triggers/T1574.002.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Legitimate setups that use similar flags</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.welivesecurity.com/2020/05/21/no-game-over-winnti-group/](https://www.welivesecurity.com/2020/05/21/no-game-over-winnti-group/)</li></ul>  |
| **Author**               | Florian Roth |
| Other Tags           | <ul><li>attack.g0044</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Winnti Pipemon Characteristics
id: 73d70463-75c9-4258-92c6-17500fe972f2
status: experimental
description: Detects specific process characteristics of Winnti Pipemon malware reported by ESET
references:
    - https://www.welivesecurity.com/2020/05/21/no-game-over-winnti-group/
tags:
    - attack.defense_evasion
    - attack.t1574.002
    - attack.t1073  # an old one
    - attack.g0044
author: Florian Roth
date: 2020/07/30
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine|contains:
            - 'setup0.exe -p'
    selection2:
        CommandLine|endswith:    
            - 'setup.exe -x:0'
            - 'setup.exe -x:1'
            - 'setup.exe -x:2'
    condition: 1 of them
falsepositives:
    - Legitimate setups that use similar flags
level: critical

```





### powershell
    
```
Get-WinEvent | where {(($_.message -match "CommandLine.*.*setup0.exe -p.*") -or ($_.message -match "CommandLine.*.*setup.exe -x:0" -or $_.message -match "CommandLine.*.*setup.exe -x:1" -or $_.message -match "CommandLine.*.*setup.exe -x:2")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.CommandLine.keyword:(*setup0.exe\\ \\-p*) OR winlog.event_data.CommandLine.keyword:(*setup.exe\\ \\-x\\:0 OR *setup.exe\\ \\-x\\:1 OR *setup.exe\\ \\-x\\:2))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/73d70463-75c9-4258-92c6-17500fe972f2 <<EOF\n{\n  "metadata": {\n    "title": "Winnti Pipemon Characteristics",\n    "description": "Detects specific process characteristics of Winnti Pipemon malware reported by ESET",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1574.002",\n      "attack.t1073",\n      "attack.g0044"\n    ],\n    "query": "(winlog.event_data.CommandLine.keyword:(*setup0.exe\\\\ \\\\-p*) OR winlog.event_data.CommandLine.keyword:(*setup.exe\\\\ \\\\-x\\\\:0 OR *setup.exe\\\\ \\\\-x\\\\:1 OR *setup.exe\\\\ \\\\-x\\\\:2))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.event_data.CommandLine.keyword:(*setup0.exe\\\\ \\\\-p*) OR winlog.event_data.CommandLine.keyword:(*setup.exe\\\\ \\\\-x\\\\:0 OR *setup.exe\\\\ \\\\-x\\\\:1 OR *setup.exe\\\\ \\\\-x\\\\:2))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Winnti Pipemon Characteristics\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(CommandLine.keyword:(*setup0.exe \\-p*) OR CommandLine.keyword:(*setup.exe \\-x\\:0 *setup.exe \\-x\\:1 *setup.exe \\-x\\:2))
```


### splunk
    
```
((CommandLine="*setup0.exe -p*") OR (CommandLine="*setup.exe -x:0" OR CommandLine="*setup.exe -x:1" OR CommandLine="*setup.exe -x:2"))
```


### logpoint
    
```
(CommandLine IN ["*setup0.exe -p*"] OR CommandLine IN ["*setup.exe -x:0", "*setup.exe -x:1", "*setup.exe -x:2"])
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*.*setup0\\.exe -p.*)|.*(?:.*.*setup\\.exe -x:0|.*.*setup\\.exe -x:1|.*.*setup\\.exe -x:2)))'
```



