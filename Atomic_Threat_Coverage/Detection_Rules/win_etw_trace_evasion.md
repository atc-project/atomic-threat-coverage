| Title                    | Disable of ETW Trace       |
|:-------------------------|:------------------|
| **Description**          | Detects a command that clears or disables any ETW trace log which could indicate a logging evasion. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1070: Indicator Removal on Host](https://attack.mitre.org/techniques/T1070)</li><li>[T1562.006: Indicator Blocking](https://attack.mitre.org/techniques/T1562.006)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1070: Indicator Removal on Host](../Triggers/T1070.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil)</li><li>[https://github.com/Neo23x0/sigma/blob/master/rules/windows/process_creation/win_mal_lockergoga.yml](https://github.com/Neo23x0/sigma/blob/master/rules/windows/process_creation/win_mal_lockergoga.yml)</li><li>[https://abuse.io/lockergoga.txt](https://abuse.io/lockergoga.txt)</li></ul>  |
| **Author**               | @neu5ron, Florian Roth |
| Other Tags           | <ul><li>car.2016-04-002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Disable of ETW Trace
id: a238b5d0-ce2d-4414-a676-7a531b3d13d6
description: Detects a command that clears or disables any ETW trace log which could indicate a logging evasion.
status: experimental
references:
    - https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil
    - https://github.com/Neo23x0/sigma/blob/master/rules/windows/process_creation/win_mal_lockergoga.yml
    - https://abuse.io/lockergoga.txt
author: '@neu5ron, Florian Roth'
date: 2019/03/22
tags:
    - attack.defense_evasion
    - attack.t1070
    - attack.t1562.006
    - car.2016-04-002
level: high
logsource:
    category: process_creation
    product: windows
detection:
    selection_clear_1:
        CommandLine: '* cl */Trace*'
    selection_clear_2:
        CommandLine: '* clear-log */Trace*'
    selection_disable_1:
        CommandLine: '* sl* /e:false*'
    selection_disable_2:
        CommandLine: '* set-log* /e:false*'
    condition: selection_clear_1 or selection_clear_2 or selection_disable_1 or selection_disable_2
falsepositives:
    - Unknown

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "CommandLine.*.* cl .*/Trace.*" -or $_.message -match "CommandLine.*.* clear-log .*/Trace.*" -or $_.message -match "CommandLine.*.* sl.* /e:false.*" -or $_.message -match "CommandLine.*.* set-log.* /e:false.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.CommandLine.keyword:*\\ cl\\ *\\/Trace* OR winlog.event_data.CommandLine.keyword:*\\ clear\\-log\\ *\\/Trace* OR winlog.event_data.CommandLine.keyword:*\\ sl*\\ \\/e\\:false* OR winlog.event_data.CommandLine.keyword:*\\ set\\-log*\\ \\/e\\:false*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/a238b5d0-ce2d-4414-a676-7a531b3d13d6 <<EOF\n{\n  "metadata": {\n    "title": "Disable of ETW Trace",\n    "description": "Detects a command that clears or disables any ETW trace log which could indicate a logging evasion.",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1070",\n      "attack.t1562.006",\n      "car.2016-04-002"\n    ],\n    "query": "(winlog.event_data.CommandLine.keyword:*\\\\ cl\\\\ *\\\\/Trace* OR winlog.event_data.CommandLine.keyword:*\\\\ clear\\\\-log\\\\ *\\\\/Trace* OR winlog.event_data.CommandLine.keyword:*\\\\ sl*\\\\ \\\\/e\\\\:false* OR winlog.event_data.CommandLine.keyword:*\\\\ set\\\\-log*\\\\ \\\\/e\\\\:false*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.event_data.CommandLine.keyword:*\\\\ cl\\\\ *\\\\/Trace* OR winlog.event_data.CommandLine.keyword:*\\\\ clear\\\\-log\\\\ *\\\\/Trace* OR winlog.event_data.CommandLine.keyword:*\\\\ sl*\\\\ \\\\/e\\\\:false* OR winlog.event_data.CommandLine.keyword:*\\\\ set\\\\-log*\\\\ \\\\/e\\\\:false*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Disable of ETW Trace\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(CommandLine.keyword:* cl *\\/Trace* OR CommandLine.keyword:* clear\\-log *\\/Trace* OR CommandLine.keyword:* sl* \\/e\\:false* OR CommandLine.keyword:* set\\-log* \\/e\\:false*)
```


### splunk
    
```
(CommandLine="* cl */Trace*" OR CommandLine="* clear-log */Trace*" OR CommandLine="* sl* /e:false*" OR CommandLine="* set-log* /e:false*")
```


### logpoint
    
```
(CommandLine="* cl */Trace*" OR CommandLine="* clear-log */Trace*" OR CommandLine="* sl* /e:false*" OR CommandLine="* set-log* /e:false*")
```


### grep
    
```
grep -P '^(?:.*(?:.*.* cl .*/Trace.*|.*.* clear-log .*/Trace.*|.*.* sl.* /e:false.*|.*.* set-log.* /e:false.*))'
```



