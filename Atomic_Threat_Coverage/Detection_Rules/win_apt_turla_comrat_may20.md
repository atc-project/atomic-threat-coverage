| Title                    | Turla Group Commands May 2020       |
|:-------------------------|:------------------|
| **Description**          | Detects commands used by Turla group as reported by ESET in May 2020 |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li><li>[T1059.001: PowerShell](https://attack.mitre.org/techniques/T1059.001)</li><li>[T1053: Scheduled Task/Job](https://attack.mitre.org/techniques/T1053)</li><li>[T1053.005: Scheduled Task](https://attack.mitre.org/techniques/T1053.005)</li><li>[T1027: Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1059.001: PowerShell](../Triggers/T1059.001.md)</li><li>[T1053.005: Scheduled Task](../Triggers/T1053.005.md)</li><li>[T1027: Obfuscated Files or Information](../Triggers/T1027.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.welivesecurity.com/wp-content/uploads/2020/05/ESET_Turla_ComRAT.pdf](https://www.welivesecurity.com/wp-content/uploads/2020/05/ESET_Turla_ComRAT.pdf)</li></ul>  |
| **Author**               | Florian Roth |
| Other Tags           | <ul><li>attack.g0010</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Turla Group Commands May 2020
id: 9e2e51c5-c699-4794-ba5a-29f5da40ac0c
status: experimental
description: Detects commands used by Turla group as reported by ESET in May 2020
references:
    - https://www.welivesecurity.com/wp-content/uploads/2020/05/ESET_Turla_ComRAT.pdf
tags:
    - attack.g0010
    - attack.execution
    - attack.t1086 # an old one
    - attack.t1059.001
    - attack.t1053 # an old one
    - attack.t1053.005
    - attack.t1027
author: Florian Roth
date: 2020/05/26
modified: 2020/08/27
logsource:
    category: process_creation
    product: windows
falsepositives:
    - Unknown
detection:
    selection1:
        CommandLine|contains:
            - 'tracert -h 10 yahoo.com'
            - '.WSqmCons))|iex;'
            - 'Fr`omBa`se6`4Str`ing'
    selection2:
        CommandLine|contains|all:
            - 'net use https://docs.live.net'
            - '@aol.co.uk'
    condition: 1 of them
level: critical

```





### powershell
    
```
Get-WinEvent | where {(($_.message -match "CommandLine.*.*tracert -h 10 yahoo.com.*" -or $_.message -match "CommandLine.*.*.WSqmCons))|iex;.*" -or $_.message -match "CommandLine.*.*Fr`omBa`se6`4Str`ing.*") -or ($_.message -match "CommandLine.*.*net use https://docs.live.net.*" -and $_.message -match "CommandLine.*.*@aol.co.uk.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.CommandLine.keyword:(*tracert\\ \\-h\\ 10\\ yahoo.com* OR *.WSqmCons\\)\\)|iex;* OR *Fr`omBa`se6`4Str`ing*) OR (winlog.event_data.CommandLine.keyword:*net\\ use\\ https\\:\\/\\/docs.live.net* AND winlog.event_data.CommandLine.keyword:*@aol.co.uk*))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/9e2e51c5-c699-4794-ba5a-29f5da40ac0c <<EOF\n{\n  "metadata": {\n    "title": "Turla Group Commands May 2020",\n    "description": "Detects commands used by Turla group as reported by ESET in May 2020",\n    "tags": [\n      "attack.g0010",\n      "attack.execution",\n      "attack.t1086",\n      "attack.t1059.001",\n      "attack.t1053",\n      "attack.t1053.005",\n      "attack.t1027"\n    ],\n    "query": "(winlog.event_data.CommandLine.keyword:(*tracert\\\\ \\\\-h\\\\ 10\\\\ yahoo.com* OR *.WSqmCons\\\\)\\\\)|iex;* OR *Fr`omBa`se6`4Str`ing*) OR (winlog.event_data.CommandLine.keyword:*net\\\\ use\\\\ https\\\\:\\\\/\\\\/docs.live.net* AND winlog.event_data.CommandLine.keyword:*@aol.co.uk*))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.event_data.CommandLine.keyword:(*tracert\\\\ \\\\-h\\\\ 10\\\\ yahoo.com* OR *.WSqmCons\\\\)\\\\)|iex;* OR *Fr`omBa`se6`4Str`ing*) OR (winlog.event_data.CommandLine.keyword:*net\\\\ use\\\\ https\\\\:\\\\/\\\\/docs.live.net* AND winlog.event_data.CommandLine.keyword:*@aol.co.uk*))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Turla Group Commands May 2020\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(CommandLine.keyword:(*tracert \\-h 10 yahoo.com* *.WSqmCons\\)\\)|iex;* *Fr`omBa`se6`4Str`ing*) OR (CommandLine.keyword:*net use https\\:\\/\\/docs.live.net* AND CommandLine.keyword:*@aol.co.uk*))
```


### splunk
    
```
((CommandLine="*tracert -h 10 yahoo.com*" OR CommandLine="*.WSqmCons))|iex;*" OR CommandLine="*Fr`omBa`se6`4Str`ing*") OR (CommandLine="*net use https://docs.live.net*" CommandLine="*@aol.co.uk*"))
```


### logpoint
    
```
(CommandLine IN ["*tracert -h 10 yahoo.com*", "*.WSqmCons))|iex;*", "*Fr`omBa`se6`4Str`ing*"] OR (CommandLine="*net use https://docs.live.net*" CommandLine="*@aol.co.uk*"))
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*.*tracert -h 10 yahoo\\.com.*|.*.*\\.WSqmCons\\)\\)\\|iex;.*|.*.*Fr`omBa`se6`4Str`ing.*)|.*(?:.*(?=.*.*net use https://docs\\.live\\.net.*)(?=.*.*@aol\\.co\\.uk.*))))'
```



