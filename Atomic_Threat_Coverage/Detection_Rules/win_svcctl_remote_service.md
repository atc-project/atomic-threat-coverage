| Title                    | Remote Service Activity via SVCCTL Named Pipe       |
|:-------------------------|:------------------|
| **Description**          | Detects remote service activity via remote access to the svcctl named pipe |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1077: Windows Admin Shares](https://attack.mitre.org/techniques/T1077)</li><li>[T1021.002: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0032_5145_network_share_object_was_accessed_detailed](../Data_Needed/DN_0032_5145_network_share_object_was_accessed_detailed.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1021.002: SMB/Windows Admin Shares](../Triggers/T1021.002.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>pentesting</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://blog.menasec.net/2019/03/threat-hunting-26-remote-windows.html](https://blog.menasec.net/2019/03/threat-hunting-26-remote-windows.html)</li></ul>  |
| **Author**               | Samir Bousseaden |


## Detection Rules

### Sigma rule

```
title: Remote Service Activity via SVCCTL Named Pipe
id: 586a8d6b-6bfe-4ad9-9d78-888cd2fe50c3
description: Detects remote service activity via remote access to the svcctl named pipe
author: Samir Bousseaden
date: 2019/04/03
references:
    - https://blog.menasec.net/2019/03/threat-hunting-26-remote-windows.html
tags:
    - attack.lateral_movement
    - attack.persistence
    - attack.t1077          # an old one
    - attack.t1021.002
logsource:
    product: windows
    service: security
    definition: 'The advanced audit policy setting "Object Access > Audit Detailed File Share" must be configured for Success/Failure'
detection:
    selection:
        EventID: 5145
        ShareName: \\*\IPC$
        RelativeTargetName: svcctl
        Accesses: '*WriteData*'
    condition: selection
falsepositives:
    - pentesting
level: medium

```





### powershell
    
```
Get-WinEvent -LogName Security | where {($_.ID -eq "5145" -and $_.message -match "ShareName.*\\.*\\IPC$" -and $_.message -match "RelativeTargetName.*svcctl" -and $_.message -match "Accesses.*.*WriteData.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND winlog.event_id:"5145" AND winlog.event_data.ShareName.keyword:\\*\\IPC$ AND RelativeTargetName:"svcctl" AND Accesses.keyword:*WriteData*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/586a8d6b-6bfe-4ad9-9d78-888cd2fe50c3 <<EOF
{
  "metadata": {
    "title": "Remote Service Activity via SVCCTL Named Pipe",
    "description": "Detects remote service activity via remote access to the svcctl named pipe",
    "tags": [
      "attack.lateral_movement",
      "attack.persistence",
      "attack.t1077",
      "attack.t1021.002"
    ],
    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"5145\" AND winlog.event_data.ShareName.keyword:\\\\*\\\\IPC$ AND RelativeTargetName:\"svcctl\" AND Accesses.keyword:*WriteData*)"
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
                    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"5145\" AND winlog.event_data.ShareName.keyword:\\\\*\\\\IPC$ AND RelativeTargetName:\"svcctl\" AND Accesses.keyword:*WriteData*)",
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
        "subject": "Sigma Rule 'Remote Service Activity via SVCCTL Named Pipe'",
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
(EventID:"5145" AND ShareName.keyword:\\*\\IPC$ AND RelativeTargetName:"svcctl" AND Accesses.keyword:*WriteData*)
```


### splunk
    
```
(source="WinEventLog:Security" EventCode="5145" ShareName="\\*\\IPC$" RelativeTargetName="svcctl" Accesses="*WriteData*")
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="5145" ShareName="\\*\\IPC$" RelativeTargetName="svcctl" Accesses="*WriteData*")
```


### grep
    
```
grep -P '^(?:.*(?=.*5145)(?=.*\\.*\IPC\$)(?=.*svcctl)(?=.*.*WriteData.*))'
```



