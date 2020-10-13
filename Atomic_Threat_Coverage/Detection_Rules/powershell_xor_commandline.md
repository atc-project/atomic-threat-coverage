| Title                    | Suspicious XOR Encoded PowerShell Command Line       |
|:-------------------------|:------------------|
| **Description**          | Detects suspicious powershell process which includes bxor command, alternative obfuscation method to b64 encoded commands. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1059.001: PowerShell](https://attack.mitre.org/techniques/T1059/001)</li><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0038_400_engine_state_is_changed_from_none_to_available](../Data_Needed/DN_0038_400_engine_state_is_changed_from_none_to_available.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1059.001: PowerShell](../Triggers/T1059.001.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Teymur Kheirkhabarov, Harish Segar (rule) |


## Detection Rules

### Sigma rule

```
title: Suspicious XOR Encoded PowerShell Command Line
id: 812837bb-b17f-45e9-8bd0-0ec35d2e3bd6
description: Detects suspicious powershell process which includes bxor command, alternative obfuscation method to b64 encoded commands.
status: experimental
author: Teymur Kheirkhabarov, Harish Segar (rule)
date: 2020/06/29
tags:
  - attack.execution
  - attack.t1059.001
  - attack.t1086  #an old one
logsource:
  product: windows
  service: powershell-classic
detection:
  selection:
    EventID: 400
    HostName: "ConsoleHost"
  filter:
    CommandLine|contains:
      - "bxor"
      - "join"
      - "char"
  condition: selection and filter
falsepositives:
  - unknown
level: medium

```





### powershell
    
```
Get-WinEvent -LogName Windows PowerShell | where {($_.ID -eq "400" -and $_.message -match "HostName.*ConsoleHost" -and ($_.message -match "CommandLine.*.*bxor.*" -or $_.message -match "CommandLine.*.*join.*" -or $_.message -match "CommandLine.*.*char.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_id:"400" AND HostName:"ConsoleHost" AND winlog.event_data.CommandLine.keyword:(*bxor* OR *join* OR *char*))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/812837bb-b17f-45e9-8bd0-0ec35d2e3bd6 <<EOF
{
  "metadata": {
    "title": "Suspicious XOR Encoded PowerShell Command Line",
    "description": "Detects suspicious powershell process which includes bxor command, alternative obfuscation method to b64 encoded commands.",
    "tags": [
      "attack.execution",
      "attack.t1059.001",
      "attack.t1086"
    ],
    "query": "(winlog.event_id:\"400\" AND HostName:\"ConsoleHost\" AND winlog.event_data.CommandLine.keyword:(*bxor* OR *join* OR *char*))"
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
                    "query": "(winlog.event_id:\"400\" AND HostName:\"ConsoleHost\" AND winlog.event_data.CommandLine.keyword:(*bxor* OR *join* OR *char*))",
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
        "subject": "Sigma Rule 'Suspicious XOR Encoded PowerShell Command Line'",
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
(EventID:"400" AND HostName:"ConsoleHost" AND CommandLine.keyword:(*bxor* *join* *char*))
```


### splunk
    
```
(source="Windows PowerShell" EventCode="400" HostName="ConsoleHost" (CommandLine="*bxor*" OR CommandLine="*join*" OR CommandLine="*char*"))
```


### logpoint
    
```
(event_id="400" HostName="ConsoleHost" CommandLine IN ["*bxor*", "*join*", "*char*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*400)(?=.*ConsoleHost)(?=.*(?:.*.*bxor.*|.*.*join.*|.*.*char.*)))'
```



