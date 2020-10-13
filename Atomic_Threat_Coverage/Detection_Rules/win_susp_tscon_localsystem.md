| Title                    | Suspicious TSCON Start       |
|:-------------------------|:------------------|
| **Description**          | Detects a tscon.exe start as LOCAL SYSTEM |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0011: Command and Control](https://attack.mitre.org/tactics/TA0011)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1219: Remote Access Software](https://attack.mitre.org/techniques/T1219)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1219: Remote Access Software](../Triggers/T1219.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[http://www.korznikov.com/2017/03/0-day-or-feature-privilege-escalation.html](http://www.korznikov.com/2017/03/0-day-or-feature-privilege-escalation.html)</li><li>[https://medium.com/@networksecurity/rdp-hijacking-how-to-hijack-rds-and-remoteapp-sessions-transparently-to-move-through-an-da2a1e73a5f6](https://medium.com/@networksecurity/rdp-hijacking-how-to-hijack-rds-and-remoteapp-sessions-transparently-to-move-through-an-da2a1e73a5f6)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Suspicious TSCON Start
id: 9847f263-4a81-424f-970c-875dab15b79b
status: experimental
description: Detects a tscon.exe start as LOCAL SYSTEM
references:
    - http://www.korznikov.com/2017/03/0-day-or-feature-privilege-escalation.html
    - https://medium.com/@networksecurity/rdp-hijacking-how-to-hijack-rds-and-remoteapp-sessions-transparently-to-move-through-an-da2a1e73a5f6
author: Florian Roth
date: 2018/03/17
tags:
    - attack.command_and_control
    - attack.t1219
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        User: NT AUTHORITY\SYSTEM
        Image: '*\tscon.exe'
    condition: selection
falsepositives:
    - Unknown
level: high

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "User.*NT AUTHORITY\\SYSTEM" -and $_.message -match "Image.*.*\\tscon.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.User:"NT\ AUTHORITY\\SYSTEM" AND winlog.event_data.Image.keyword:*\\tscon.exe)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/9847f263-4a81-424f-970c-875dab15b79b <<EOF
{
  "metadata": {
    "title": "Suspicious TSCON Start",
    "description": "Detects a tscon.exe start as LOCAL SYSTEM",
    "tags": [
      "attack.command_and_control",
      "attack.t1219"
    ],
    "query": "(winlog.event_data.User:\"NT\\ AUTHORITY\\\\SYSTEM\" AND winlog.event_data.Image.keyword:*\\\\tscon.exe)"
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
                    "query": "(winlog.event_data.User:\"NT\\ AUTHORITY\\\\SYSTEM\" AND winlog.event_data.Image.keyword:*\\\\tscon.exe)",
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
        "subject": "Sigma Rule 'Suspicious TSCON Start'",
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
(User:"NT AUTHORITY\\SYSTEM" AND Image.keyword:*\\tscon.exe)
```


### splunk
    
```
(User="NT AUTHORITY\\SYSTEM" Image="*\\tscon.exe")
```


### logpoint
    
```
(User="NT AUTHORITY\\SYSTEM" Image="*\\tscon.exe")
```


### grep
    
```
grep -P '^(?:.*(?=.*NT AUTHORITY\SYSTEM)(?=.*.*\tscon\.exe))'
```



