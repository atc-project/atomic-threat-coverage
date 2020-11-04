| Title                    | Process Dump via Rundll32 and Comsvcs.dll       |
|:-------------------------|:------------------|
| **Description**          | Detects a process memory dump performed via ordinal function 24 in comsvcs.dll |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1036: Masquerading](https://attack.mitre.org/techniques/T1036)</li><li>[T1003: OS Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1036: Masquerading](../Triggers/T1036.md)</li><li>[T1003: OS Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unlikely, because no one should dump the process memory in that way</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://twitter.com/shantanukhande/status/1229348874298388484](https://twitter.com/shantanukhande/status/1229348874298388484)</li></ul>  |
| **Author**               | Florian Roth |
| Other Tags           | <ul><li>car.2013-05-009</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Process Dump via Rundll32 and Comsvcs.dll
id: 646ea171-dded-4578-8a4d-65e9822892e3
description: Detects a process memory dump performed via ordinal function 24 in comsvcs.dll
status: experimental
references:
    - https://twitter.com/shantanukhande/status/1229348874298388484
author: Florian Roth
date: 2020/02/18
tags:
    - attack.defense_evasion
    - attack.t1036
    - attack.credential_access
    - attack.t1003
    - car.2013-05-009
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'comsvcs.dll,#24'
            - 'comsvcs.dll,MiniDump'
    condition: selection
falsepositives:
    - Unlikely, because no one should dump the process memory in that way
level: high

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "CommandLine.*.*comsvcs.dll,#24.*" -or $_.message -match "CommandLine.*.*comsvcs.dll,MiniDump.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.CommandLine.keyword:(*comsvcs.dll,#24* OR *comsvcs.dll,MiniDump*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/646ea171-dded-4578-8a4d-65e9822892e3 <<EOF
{
  "metadata": {
    "title": "Process Dump via Rundll32 and Comsvcs.dll",
    "description": "Detects a process memory dump performed via ordinal function 24 in comsvcs.dll",
    "tags": [
      "attack.defense_evasion",
      "attack.t1036",
      "attack.credential_access",
      "attack.t1003",
      "car.2013-05-009"
    ],
    "query": "winlog.event_data.CommandLine.keyword:(*comsvcs.dll,#24* OR *comsvcs.dll,MiniDump*)"
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
                    "query": "winlog.event_data.CommandLine.keyword:(*comsvcs.dll,#24* OR *comsvcs.dll,MiniDump*)",
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
      "email": {
        "to": "root@localhost",
        "subject": "Sigma Rule 'Process Dump via Rundll32 and Comsvcs.dll'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}{{_source}}\n================================================================================\n{{/ctx.payload.hits.hits}}",
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
CommandLine.keyword:(*comsvcs.dll,#24* *comsvcs.dll,MiniDump*)
```


### splunk
    
```
(CommandLine="*comsvcs.dll,#24*" OR CommandLine="*comsvcs.dll,MiniDump*")
```


### logpoint
    
```
CommandLine IN ["*comsvcs.dll,#24*", "*comsvcs.dll,MiniDump*"]
```


### grep
    
```
grep -P '^(?:.*.*comsvcs\.dll,#24.*|.*.*comsvcs\.dll,MiniDump.*)'
```



