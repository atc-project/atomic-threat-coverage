| Title                    | Encoded FromBase64String       |
|:-------------------------|:------------------|
| **Description**          | Detects a base64 encoded FromBase64String keyword in a process command line |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1140: Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140)</li><li>[T1059.001: PowerShell](https://attack.mitre.org/techniques/T1059/001)</li><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1140: Deobfuscate/Decode Files or Information](../Triggers/T1140.md)</li><li>[T1059.001: PowerShell](../Triggers/T1059.001.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Encoded FromBase64String
id: fdb62a13-9a81-4e5c-a38f-ea93a16f6d7c
status: experimental
description: Detects a base64 encoded FromBase64String keyword in a process command line
author: Florian Roth
date: 2019/08/24
tags:
    - attack.defense_evasion
    - attack.t1140
    - attack.execution
    - attack.t1059.001
    - attack.t1086  # an old one
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|base64offset|contains: '::FromBase64String'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - unknown
level: critical

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "CommandLine.*.*OjpGcm9tQmFzZTY0U3RyaW5n.*" -or $_.message -match "CommandLine.*.*o6RnJvbUJhc2U2NFN0cmluZ.*" -or $_.message -match "CommandLine.*.*6OkZyb21CYXNlNjRTdHJpbm.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.CommandLine.keyword:(*OjpGcm9tQmFzZTY0U3RyaW5n* OR *o6RnJvbUJhc2U2NFN0cmluZ* OR *6OkZyb21CYXNlNjRTdHJpbm*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/fdb62a13-9a81-4e5c-a38f-ea93a16f6d7c <<EOF
{
  "metadata": {
    "title": "Encoded FromBase64String",
    "description": "Detects a base64 encoded FromBase64String keyword in a process command line",
    "tags": [
      "attack.defense_evasion",
      "attack.t1140",
      "attack.execution",
      "attack.t1059.001",
      "attack.t1086"
    ],
    "query": "winlog.event_data.CommandLine.keyword:(*OjpGcm9tQmFzZTY0U3RyaW5n* OR *o6RnJvbUJhc2U2NFN0cmluZ* OR *6OkZyb21CYXNlNjRTdHJpbm*)"
  },
  "trigger": {
    "schedule": {
      "interval": "30m"
    }
  },
  "input": {
    "search": {
      "request": {
        "body": {
          "size": 0,
          "query": {
            "bool": {
              "must": [
                {
                  "query_string": {
                    "query": "winlog.event_data.CommandLine.keyword:(*OjpGcm9tQmFzZTY0U3RyaW5n* OR *o6RnJvbUJhc2U2NFN0cmluZ* OR *6OkZyb21CYXNlNjRTdHJpbm*)",
                    "analyze_wildcard": true
                  }
                }
              ],
              "filter": {
                "range": {
                  "timestamp": {
                    "gte": "now-30m/m"
                  }
                }
              }
            }
          }
        },
        "indices": [
          "winlogbeat-*"
        ]
      }
    }
  },
  "condition": {
    "compare": {
      "ctx.payload.hits.total": {
        "not_eq": 0
      }
    }
  },
  "actions": {
    "send_email": {
      "throttle_period": "15m",
      "email": {
        "profile": "standard",
        "from": "root@localhost",
        "to": "root@localhost",
        "subject": "Sigma Rule 'Encoded FromBase64String'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\n      CommandLine = {{_source.CommandLine}}\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\n{{/ctx.payload.hits.hits}}",
        "attachments": {
          "data.json": {
            "data": {
              "format": "json"
            }
          }
        }
      }
    }
  }
}
EOF

```


### graylog
    
```
CommandLine.keyword:(*OjpGcm9tQmFzZTY0U3RyaW5n* *o6RnJvbUJhc2U2NFN0cmluZ* *6OkZyb21CYXNlNjRTdHJpbm*)
```


### splunk
    
```
(CommandLine="*OjpGcm9tQmFzZTY0U3RyaW5n*" OR CommandLine="*o6RnJvbUJhc2U2NFN0cmluZ*" OR CommandLine="*6OkZyb21CYXNlNjRTdHJpbm*") | table CommandLine,ParentCommandLine
```


### logpoint
    
```
CommandLine IN ["*OjpGcm9tQmFzZTY0U3RyaW5n*", "*o6RnJvbUJhc2U2NFN0cmluZ*", "*6OkZyb21CYXNlNjRTdHJpbm*"]
```


### grep
    
```
grep -P '^(?:.*.*OjpGcm9tQmFzZTY0U3RyaW5n.*|.*.*o6RnJvbUJhc2U2NFN0cmluZ.*|.*.*6OkZyb21CYXNlNjRTdHJpbm.*)'
```



