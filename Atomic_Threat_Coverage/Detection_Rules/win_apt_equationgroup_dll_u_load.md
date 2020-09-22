| Title                    | Equation Group DLL_U Load       |
|:-------------------------|:------------------|
| **Description**          | Detects a specific tool and export used by EquationGroup |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1085: Rundll32](https://attack.mitre.org/techniques/T1085)</li><li>[T1218.011: Rundll32](https://attack.mitre.org/techniques/T1218.011)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1218.011: Rundll32](../Triggers/T1218.011.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://github.com/adamcaudill/EquationGroupLeak/search?utf8=%E2%9C%93&q=dll_u&type=](https://github.com/adamcaudill/EquationGroupLeak/search?utf8=%E2%9C%93&q=dll_u&type=)</li><li>[https://securelist.com/apt-slingshot/84312/](https://securelist.com/apt-slingshot/84312/)</li><li>[https://twitter.com/cyb3rops/status/972186477512839170](https://twitter.com/cyb3rops/status/972186477512839170)</li></ul>  |
| **Author**               | Florian Roth |
| Other Tags           | <ul><li>attack.g0020</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Equation Group DLL_U Load
id: d465d1d8-27a2-4cca-9621-a800f37cf72e
author: Florian Roth
date: 2019/03/04
modified: 2020/08/27
description: Detects a specific tool and export used by EquationGroup
references:
    - https://github.com/adamcaudill/EquationGroupLeak/search?utf8=%E2%9C%93&q=dll_u&type=
    - https://securelist.com/apt-slingshot/84312/
    - https://twitter.com/cyb3rops/status/972186477512839170
tags:
    - attack.g0020
    - attack.defense_evasion
    - attack.t1085 # an old one
    - attack.t1218.011
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        Image: '*\rundll32.exe'
        CommandLine: '*,dll_u'
    selection2:
        CommandLine: '* -export dll_u *'
    condition: 1 of them
falsepositives:
    - Unknown
level: critical

```





### powershell
    
```
Get-WinEvent | where {(($_.message -match "Image.*.*\\\\rundll32.exe" -and $_.message -match "CommandLine.*.*,dll_u") -or $_.message -match "CommandLine.*.* -export dll_u .*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
((winlog.event_data.Image.keyword:*\\\\rundll32.exe AND winlog.event_data.CommandLine.keyword:*,dll_u) OR winlog.event_data.CommandLine.keyword:*\\ \\-export\\ dll_u\\ *)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/d465d1d8-27a2-4cca-9621-a800f37cf72e <<EOF\n{\n  "metadata": {\n    "title": "Equation Group DLL_U Load",\n    "description": "Detects a specific tool and export used by EquationGroup",\n    "tags": [\n      "attack.g0020",\n      "attack.defense_evasion",\n      "attack.t1085",\n      "attack.t1218.011"\n    ],\n    "query": "((winlog.event_data.Image.keyword:*\\\\\\\\rundll32.exe AND winlog.event_data.CommandLine.keyword:*,dll_u) OR winlog.event_data.CommandLine.keyword:*\\\\ \\\\-export\\\\ dll_u\\\\ *)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((winlog.event_data.Image.keyword:*\\\\\\\\rundll32.exe AND winlog.event_data.CommandLine.keyword:*,dll_u) OR winlog.event_data.CommandLine.keyword:*\\\\ \\\\-export\\\\ dll_u\\\\ *)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Equation Group DLL_U Load\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((Image.keyword:*\\\\rundll32.exe AND CommandLine.keyword:*,dll_u) OR CommandLine.keyword:* \\-export dll_u *)
```


### splunk
    
```
((Image="*\\\\rundll32.exe" CommandLine="*,dll_u") OR CommandLine="* -export dll_u *")
```


### logpoint
    
```
((Image="*\\\\rundll32.exe" CommandLine="*,dll_u") OR CommandLine="* -export dll_u *")
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*(?=.*.*\\rundll32\\.exe)(?=.*.*,dll_u))|.*.* -export dll_u .*))'
```



