| Title                    | Ps.exe Renamed SysInternals Tool       |
|:-------------------------|:------------------|
| **Description**          | Detects renamed SysInternals tool execution with a binary named ps.exe as used by Dragonfly APT group and documented in TA17-293A report |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1036: Masquerading](https://attack.mitre.org/techniques/T1036)</li><li>[T1036.003: Rename System Utilities](https://attack.mitre.org/techniques/T1036/003)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1036.003: Rename System Utilities](../Triggers/T1036.003.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Renamed SysInternals tool</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://www.us-cert.gov/ncas/alerts/TA17-293A](https://www.us-cert.gov/ncas/alerts/TA17-293A)</li></ul>  |
| **Author**               | Florian Roth |
| Other Tags           | <ul><li>attack.g0035</li><li>car.2013-05-009</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Ps.exe Renamed SysInternals Tool
id: 18da1007-3f26-470f-875d-f77faf1cab31
description: Detects renamed SysInternals tool execution with a binary named ps.exe as used by Dragonfly APT group and documented in TA17-293A report
references:
    - https://www.us-cert.gov/ncas/alerts/TA17-293A
tags:
    - attack.defense_evasion
    - attack.g0035
    - attack.t1036 # an old one
    - attack.t1036.003
    - car.2013-05-009
author: Florian Roth
date: 2017/10/22
modified: 2020/08/27
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine: 'ps.exe -accepteula'
    condition: selection
falsepositives:
    - Renamed SysInternals tool
level: high
```





### powershell
    
```
Get-WinEvent | where {$_.message -match "CommandLine.*ps.exe -accepteula" } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.CommandLine:"ps.exe\\ \\-accepteula"
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/18da1007-3f26-470f-875d-f77faf1cab31 <<EOF\n{\n  "metadata": {\n    "title": "Ps.exe Renamed SysInternals Tool",\n    "description": "Detects renamed SysInternals tool execution with a binary named ps.exe as used by Dragonfly APT group and documented in TA17-293A report",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.g0035",\n      "attack.t1036",\n      "attack.t1036.003",\n      "car.2013-05-009"\n    ],\n    "query": "winlog.event_data.CommandLine:\\"ps.exe\\\\ \\\\-accepteula\\""\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "winlog.event_data.CommandLine:\\"ps.exe\\\\ \\\\-accepteula\\"",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Ps.exe Renamed SysInternals Tool\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
CommandLine:"ps.exe \\-accepteula"
```


### splunk
    
```
CommandLine="ps.exe -accepteula"
```


### logpoint
    
```
CommandLine="ps.exe -accepteula"
```


### grep
    
```
grep -P '^ps\\.exe -accepteula'
```



