| Title                    | MSTSC Shadowing       |
|:-------------------------|:------------------|
| **Description**          | Detects RDP session hijacking by using MSTSC shadowing |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1563.002: RDP Hijacking](https://attack.mitre.org/techniques/T1563/002)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1563.002: RDP Hijacking](../Triggers/T1563.002.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://twitter.com/kmkz_security/status/1220694202301976576](https://twitter.com/kmkz_security/status/1220694202301976576)</li><li>[https://github.com/kmkz/Pentesting/blob/master/Post-Exploitation-Cheat-Sheet](https://github.com/kmkz/Pentesting/blob/master/Post-Exploitation-Cheat-Sheet)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: MSTSC Shadowing
id: 6ba5a05f-b095-4f0a-8654-b825f4f16334
description: Detects RDP session hijacking by using MSTSC shadowing
status: experimental
author: Florian Roth
date: 2020/01/24
modified: 2020/09/06
references:
    - https://twitter.com/kmkz_security/status/1220694202301976576
    - https://github.com/kmkz/Pentesting/blob/master/Post-Exploitation-Cheat-Sheet
tags:
    - attack.lateral_movement
    - attack.t1563.002    
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all: 
            - 'noconsentprompt'
            - 'shadow:'
    condition: selection
falsepositives:
    - Unknown
level: high

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "CommandLine.*.*noconsentprompt.*" -and $_.message -match "CommandLine.*.*shadow:.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.CommandLine.keyword:*noconsentprompt* AND winlog.event_data.CommandLine.keyword:*shadow\\:*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/6ba5a05f-b095-4f0a-8654-b825f4f16334 <<EOF\n{\n  "metadata": {\n    "title": "MSTSC Shadowing",\n    "description": "Detects RDP session hijacking by using MSTSC shadowing",\n    "tags": [\n      "attack.lateral_movement",\n      "attack.t1563.002"\n    ],\n    "query": "(winlog.event_data.CommandLine.keyword:*noconsentprompt* AND winlog.event_data.CommandLine.keyword:*shadow\\\\:*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.event_data.CommandLine.keyword:*noconsentprompt* AND winlog.event_data.CommandLine.keyword:*shadow\\\\:*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'MSTSC Shadowing\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(CommandLine.keyword:*noconsentprompt* AND CommandLine.keyword:*shadow\\:*)
```


### splunk
    
```
(CommandLine="*noconsentprompt*" CommandLine="*shadow:*")
```


### logpoint
    
```
(CommandLine="*noconsentprompt*" CommandLine="*shadow:*")
```


### grep
    
```
grep -P '^(?:.*(?=.*.*noconsentprompt.*)(?=.*.*shadow:.*))'
```



