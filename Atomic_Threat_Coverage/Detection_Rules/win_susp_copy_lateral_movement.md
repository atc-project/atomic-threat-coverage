| Title                    | Copy from Admin Share       |
|:-------------------------|:------------------|
| **Description**          | Detects a suspicious copy command from a remote C$ or ADMIN$ share |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li><li>[TA0011: Command and Control](https://attack.mitre.org/tactics/TA0011)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1021.002: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002)</li><li>[T1105: Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105)</li><li>[T1077: Windows Admin Shares](https://attack.mitre.org/techniques/T1077)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1021.002: SMB/Windows Admin Shares](../Triggers/T1021.002.md)</li><li>[T1105: Ingress Tool Transfer](../Triggers/T1105.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Administrative scripts</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://twitter.com/SBousseaden/status/1211636381086339073](https://twitter.com/SBousseaden/status/1211636381086339073)</li></ul>  |
| **Author**               | Florian Roth |
| Other Tags           | <ul><li>attack.s0106</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Copy from Admin Share
id: 855bc8b5-2ae8-402e-a9ed-b889e6df1900
status: experimental
description: Detects a suspicious copy command from a remote C$ or ADMIN$ share
references:
    - https://twitter.com/SBousseaden/status/1211636381086339073
author: Florian Roth
date: 2019/12/30
modified: 2020/09/05
tags:
    - attack.lateral_movement
    - attack.t1021.002
    - attack.command_and_control 
    - attack.t1105
    - attack.s0106
    - attack.t1077      # an old one
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'copy *\c$'
            - 'copy *\ADMIN$'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Administrative scripts
level: high

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "CommandLine.*.*copy .*\\\\c$.*" -or $_.message -match "CommandLine.*.*copy .*\\\\ADMIN$.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.CommandLine.keyword:(*copy\\ *\\\\c$* OR *copy\\ *\\\\ADMIN$*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/855bc8b5-2ae8-402e-a9ed-b889e6df1900 <<EOF\n{\n  "metadata": {\n    "title": "Copy from Admin Share",\n    "description": "Detects a suspicious copy command from a remote C$ or ADMIN$ share",\n    "tags": [\n      "attack.lateral_movement",\n      "attack.t1021.002",\n      "attack.command_and_control",\n      "attack.t1105",\n      "attack.s0106",\n      "attack.t1077"\n    ],\n    "query": "winlog.event_data.CommandLine.keyword:(*copy\\\\ *\\\\\\\\c$* OR *copy\\\\ *\\\\\\\\ADMIN$*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "winlog.event_data.CommandLine.keyword:(*copy\\\\ *\\\\\\\\c$* OR *copy\\\\ *\\\\\\\\ADMIN$*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Copy from Admin Share\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
CommandLine.keyword:(*copy *\\\\c$* *copy *\\\\ADMIN$*)
```


### splunk
    
```
(CommandLine="*copy *\\\\c$*" OR CommandLine="*copy *\\\\ADMIN$*") | table CommandLine,ParentCommandLine
```


### logpoint
    
```
CommandLine IN ["*copy *\\\\c$*", "*copy *\\\\ADMIN$*"]
```


### grep
    
```
grep -P '^(?:.*.*copy .*\\c\\$.*|.*.*copy .*\\ADMIN\\$.*)'
```



