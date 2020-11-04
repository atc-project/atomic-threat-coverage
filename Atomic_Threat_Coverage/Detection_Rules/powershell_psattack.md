| Title                    | PowerShell PSAttack       |
|:-------------------------|:------------------|
| **Description**          | Detects the use of PSAttack PowerShell hack tool |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0037_4103_windows_powershell_executing_pipeline](../Data_Needed/DN_0037_4103_windows_powershell_executing_pipeline.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Pentesters</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://adsecurity.org/?p=2921](https://adsecurity.org/?p=2921)</li></ul>  |
| **Author**               | Sean Metcalf (source), Florian Roth (rule) |


## Detection Rules

### Sigma rule

```
title: PowerShell PSAttack
id: b7ec41a4-042c-4f31-a5db-d0fcde9fa5c5
status: experimental
description: Detects the use of PSAttack PowerShell hack tool
references:
    - https://adsecurity.org/?p=2921
tags:
    - attack.execution
    - attack.t1086
author: Sean Metcalf (source), Florian Roth (rule)
date: 2017/03/05
logsource:
    product: windows
    service: powershell
    definition: 'It is recommended to use the new "Script Block Logging" of PowerShell v5 https://adsecurity.org/?p=2277'
detection:
    selection:
        EventID: 4103
    keyword:
        - 'PS ATTACK!!!'
    condition: all of them
falsepositives:
    - Pentesters
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {($_.ID -eq "4103" -and $_.message -match "PS ATTACK!!!") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_id:"4103" AND "PS\ ATTACK\!\!\!")
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/b7ec41a4-042c-4f31-a5db-d0fcde9fa5c5 <<EOF
{
  "metadata": {
    "title": "PowerShell PSAttack",
    "description": "Detects the use of PSAttack PowerShell hack tool",
    "tags": [
      "attack.execution",
      "attack.t1086"
    ],
    "query": "(winlog.event_id:\"4103\" AND \"PS\\ ATTACK\\!\\!\\!\")"
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
                    "query": "(winlog.event_id:\"4103\" AND \"PS\\ ATTACK\\!\\!\\!\")",
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
        "subject": "Sigma Rule 'PowerShell PSAttack'",
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
(EventID:"4103" AND "PS ATTACK\!\!\!")
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="4103" "PS ATTACK!!!")
```


### logpoint
    
```
(event_id="4103" "PS ATTACK!!!")
```


### grep
    
```
grep -P '^(?:.*(?=.*4103)(?=.*PS ATTACK!!!))'
```



