| Title                    | Suspicious RDP Redirect Using TSCON       |
|:-------------------------|:------------------|
| **Description**          | Detects a suspicious RDP session redirect using tscon.exe |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1563.002: RDP Hijacking](https://attack.mitre.org/techniques/T1563/002)</li><li>[T1076: Remote Desktop Protocol](https://attack.mitre.org/techniques/T1076)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1563.002: RDP Hijacking](../Triggers/T1563.002.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[http://www.korznikov.com/2017/03/0-day-or-feature-privilege-escalation.html](http://www.korznikov.com/2017/03/0-day-or-feature-privilege-escalation.html)</li><li>[https://medium.com/@networksecurity/rdp-hijacking-how-to-hijack-rds-and-remoteapp-sessions-transparently-to-move-through-an-da2a1e73a5f6](https://medium.com/@networksecurity/rdp-hijacking-how-to-hijack-rds-and-remoteapp-sessions-transparently-to-move-through-an-da2a1e73a5f6)</li></ul>  |
| **Author**               | Florian Roth |
| Other Tags           | <ul><li>car.2013-07-002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Suspicious RDP Redirect Using TSCON
id: f72aa3e8-49f9-4c7d-bd74-f8ab84ff9bbb
status: experimental
description: Detects a suspicious RDP session redirect using tscon.exe
references:
    - http://www.korznikov.com/2017/03/0-day-or-feature-privilege-escalation.html
    - https://medium.com/@networksecurity/rdp-hijacking-how-to-hijack-rds-and-remoteapp-sessions-transparently-to-move-through-an-da2a1e73a5f6
tags:
    - attack.lateral_movement
    - attack.t1563.002
    - attack.t1076      # an old one
    - car.2013-07-002
author: Florian Roth
date: 2018/03/17
modified: 2020/08/29
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine: '* /dest:rdp-tcp:*'
    condition: selection
falsepositives:
    - Unknown
level: high

```





### powershell
    
```
Get-WinEvent | where {$_.message -match "CommandLine.*.* /dest:rdp-tcp:.*" } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.CommandLine.keyword:*\ \/dest\:rdp\-tcp\:*
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/f72aa3e8-49f9-4c7d-bd74-f8ab84ff9bbb <<EOF
{
  "metadata": {
    "title": "Suspicious RDP Redirect Using TSCON",
    "description": "Detects a suspicious RDP session redirect using tscon.exe",
    "tags": [
      "attack.lateral_movement",
      "attack.t1563.002",
      "attack.t1076",
      "car.2013-07-002"
    ],
    "query": "winlog.event_data.CommandLine.keyword:*\\ \\/dest\\:rdp\\-tcp\\:*"
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
                    "query": "winlog.event_data.CommandLine.keyword:*\\ \\/dest\\:rdp\\-tcp\\:*",
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
        "subject": "Sigma Rule 'Suspicious RDP Redirect Using TSCON'",
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
CommandLine.keyword:* \/dest\:rdp\-tcp\:*
```


### splunk
    
```
CommandLine="* /dest:rdp-tcp:*"
```


### logpoint
    
```
CommandLine="* /dest:rdp-tcp:*"
```


### grep
    
```
grep -P '^.* /dest:rdp-tcp:.*'
```



