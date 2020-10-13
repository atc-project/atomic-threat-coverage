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
(winlog.event_data.CommandLine.keyword:*noconsentprompt* AND winlog.event_data.CommandLine.keyword:*shadow\:*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/6ba5a05f-b095-4f0a-8654-b825f4f16334 <<EOF
{
  "metadata": {
    "title": "MSTSC Shadowing",
    "description": "Detects RDP session hijacking by using MSTSC shadowing",
    "tags": [
      "attack.lateral_movement",
      "attack.t1563.002"
    ],
    "query": "(winlog.event_data.CommandLine.keyword:*noconsentprompt* AND winlog.event_data.CommandLine.keyword:*shadow\\:*)"
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
                    "query": "(winlog.event_data.CommandLine.keyword:*noconsentprompt* AND winlog.event_data.CommandLine.keyword:*shadow\\:*)",
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
        "subject": "Sigma Rule 'MSTSC Shadowing'",
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
(CommandLine.keyword:*noconsentprompt* AND CommandLine.keyword:*shadow\:*)
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



