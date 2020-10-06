| Title                    | FromBase64String Command Line       |
|:-------------------------|:------------------|
| **Description**          | Detects suspicious FromBase64String expressions in command line arguments |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1027: Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027)</li><li>[T1140: Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140)</li><li>[T1059.001: PowerShell](https://attack.mitre.org/techniques/T1059/001)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1027: Obfuscated Files or Information](../Triggers/T1027.md)</li><li>[T1140: Deobfuscate/Decode Files or Information](../Triggers/T1140.md)</li><li>[T1059.001: PowerShell](../Triggers/T1059.001.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Administrative script libraries</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://gist.github.com/Neo23x0/6af876ee72b51676c82a2db8d2cd3639](https://gist.github.com/Neo23x0/6af876ee72b51676c82a2db8d2cd3639)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: FromBase64String Command Line
id: e32d4572-9826-4738-b651-95fa63747e8a
status: experimental
description: Detects suspicious FromBase64String expressions in command line arguments
references:
    - https://gist.github.com/Neo23x0/6af876ee72b51676c82a2db8d2cd3639
author: Florian Roth
date: 2020/01/29
modified: 2020/09/06
tags: 
    - attack.t1027
    - attack.defense_evasion
    - attack.t1140
    - attack.t1059.001    
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: '::FromBase64String('
    condition: selection
falsepositives:
    - Administrative script libraries
level: high

```





### powershell
    
```
Get-WinEvent | where {$_.message -match "CommandLine.*.*::FromBase64String(.*" } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.CommandLine.keyword:*\\:\\:FromBase64String\\(*
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/e32d4572-9826-4738-b651-95fa63747e8a <<EOF\n{\n  "metadata": {\n    "title": "FromBase64String Command Line",\n    "description": "Detects suspicious FromBase64String expressions in command line arguments",\n    "tags": [\n      "attack.t1027",\n      "attack.defense_evasion",\n      "attack.t1140",\n      "attack.t1059.001"\n    ],\n    "query": "winlog.event_data.CommandLine.keyword:*\\\\:\\\\:FromBase64String\\\\(*"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "winlog.event_data.CommandLine.keyword:*\\\\:\\\\:FromBase64String\\\\(*",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'FromBase64String Command Line\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
CommandLine.keyword:*\\:\\:FromBase64String\\(*
```


### splunk
    
```
CommandLine="*::FromBase64String(*"
```


### logpoint
    
```
CommandLine="*::FromBase64String(*"
```


### grep
    
```
grep -P '^.*::FromBase64String\\(.*'
```



