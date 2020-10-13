| Title                    | Persistence and Execution at Scale via GPO Scheduled Task       |
|:-------------------------|:------------------|
| **Description**          | Detect lateral movement using GPO scheduled task, usually used to deploy ransomware at scale |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1053: Scheduled Task/Job](https://attack.mitre.org/techniques/T1053)</li><li>[T1053.005: Scheduled Task](https://attack.mitre.org/techniques/T1053/005)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0032_5145_network_share_object_was_accessed_detailed](../Data_Needed/DN_0032_5145_network_share_object_was_accessed_detailed.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1053.005: Scheduled Task](../Triggers/T1053.005.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>if the source IP is not localhost then it's super suspicious, better to monitor both local and remote changes to GPO scheduledtasks</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://twitter.com/menasec1/status/1106899890377052160](https://twitter.com/menasec1/status/1106899890377052160)</li><li>[https://www.secureworks.com/blog/ransomware-as-a-distraction](https://www.secureworks.com/blog/ransomware-as-a-distraction)</li></ul>  |
| **Author**               | Samir Bousseaden |


## Detection Rules

### Sigma rule

```
title: Persistence and Execution at Scale via GPO Scheduled Task
id: a8f29a7b-b137-4446-80a0-b804272f3da2
description: Detect lateral movement using GPO scheduled task, usually used to deploy ransomware at scale
author: Samir Bousseaden
date: 2019/04/03
references:
    - https://twitter.com/menasec1/status/1106899890377052160
    - https://www.secureworks.com/blog/ransomware-as-a-distraction
tags:
    - attack.persistence
    - attack.lateral_movement
    - attack.t1053          # an old one
    - attack.t1053.005
logsource:
    product: windows
    service: security
    definition: 'The advanced audit policy setting "Object Access > Audit Detailed File Share" must be configured for Success/Failure'
detection:
    selection:
        EventID: 5145
        ShareName: \\*\SYSVOL
        RelativeTargetName: '*ScheduledTasks.xml'
        Accesses: '*WriteData*'
    condition: selection
falsepositives:
    - if the source IP is not localhost then it's super suspicious, better to monitor both local and remote changes to GPO scheduledtasks
level: high

```





### powershell
    
```
Get-WinEvent -LogName Security | where {($_.ID -eq "5145" -and $_.message -match "ShareName.*\\.*\\SYSVOL" -and $_.message -match "RelativeTargetName.*.*ScheduledTasks.xml" -and $_.message -match "Accesses.*.*WriteData.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND winlog.event_id:"5145" AND winlog.event_data.ShareName.keyword:\\*\\SYSVOL AND RelativeTargetName.keyword:*ScheduledTasks.xml AND Accesses.keyword:*WriteData*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/a8f29a7b-b137-4446-80a0-b804272f3da2 <<EOF
{
  "metadata": {
    "title": "Persistence and Execution at Scale via GPO Scheduled Task",
    "description": "Detect lateral movement using GPO scheduled task, usually used to deploy ransomware at scale",
    "tags": [
      "attack.persistence",
      "attack.lateral_movement",
      "attack.t1053",
      "attack.t1053.005"
    ],
    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"5145\" AND winlog.event_data.ShareName.keyword:\\\\*\\\\SYSVOL AND RelativeTargetName.keyword:*ScheduledTasks.xml AND Accesses.keyword:*WriteData*)"
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
                    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"5145\" AND winlog.event_data.ShareName.keyword:\\\\*\\\\SYSVOL AND RelativeTargetName.keyword:*ScheduledTasks.xml AND Accesses.keyword:*WriteData*)",
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
        "subject": "Sigma Rule 'Persistence and Execution at Scale via GPO Scheduled Task'",
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
(EventID:"5145" AND ShareName.keyword:\\*\\SYSVOL AND RelativeTargetName.keyword:*ScheduledTasks.xml AND Accesses.keyword:*WriteData*)
```


### splunk
    
```
(source="WinEventLog:Security" EventCode="5145" ShareName="\\*\\SYSVOL" RelativeTargetName="*ScheduledTasks.xml" Accesses="*WriteData*")
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="5145" ShareName="\\*\\SYSVOL" RelativeTargetName="*ScheduledTasks.xml" Accesses="*WriteData*")
```


### grep
    
```
grep -P '^(?:.*(?=.*5145)(?=.*\\.*\SYSVOL)(?=.*.*ScheduledTasks\.xml)(?=.*.*WriteData.*))'
```



