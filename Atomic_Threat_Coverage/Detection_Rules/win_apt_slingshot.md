| Title                    | Defrag Deactivation       |
|:-------------------------|:------------------|
| **Description**          | Detects the deactivation of the Scheduled defragmentation task as seen by Slingshot APT group |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1053: Scheduled Task/Job](https://attack.mitre.org/techniques/T1053)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://securelist.com/apt-slingshot/84312/](https://securelist.com/apt-slingshot/84312/)</li></ul>  |
| **Author**               | Florian Roth |
| Other Tags           | <ul><li>attack.s0111</li></ul> | 

## Detection Rules

### Sigma rule

```
action: global
title: Defrag Deactivation
id: 958d81aa-8566-4cea-a565-59ccd4df27b0
author: Florian Roth
date: 2019/03/04
description: Detects the deactivation of the Scheduled defragmentation task as seen by Slingshot APT group
references:
    - https://securelist.com/apt-slingshot/84312/
tags:
    - attack.persistence
    - attack.t1053
    - attack.s0111
detection:
    condition: 1 of them
falsepositives:
    - Unknown
level: medium
---
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine:
            - '*schtasks* /delete *Defrag\ScheduledDefrag*'
---
logsource:
    product: windows
    service: security
    definition: 'Requirements: Audit Policy : Audit Other Object Access Events > Success'
detection:
    selection2:
        EventID: 4701
        TaskName: '\Microsoft\Windows\Defrag\ScheduledDefrag'

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*schtasks.* /delete .*Defrag\\ScheduledDefrag.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
Get-WinEvent -LogName Security | where {($_.ID -eq "4701" -and $_.message -match "TaskName.*\\Microsoft\\Windows\\Defrag\\ScheduledDefrag") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.CommandLine.keyword:(*schtasks*\ \/delete\ *Defrag\\ScheduledDefrag*)
(winlog.channel:"Security" AND winlog.event_id:"4701" AND TaskName:"\\Microsoft\\Windows\\Defrag\\ScheduledDefrag")
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/958d81aa-8566-4cea-a565-59ccd4df27b0 <<EOF
{
  "metadata": {
    "title": "Defrag Deactivation",
    "description": "Detects the deactivation of the Scheduled defragmentation task as seen by Slingshot APT group",
    "tags": [
      "attack.persistence",
      "attack.t1053",
      "attack.s0111"
    ],
    "query": "winlog.event_data.CommandLine.keyword:(*schtasks*\\ \\/delete\\ *Defrag\\\\ScheduledDefrag*)"
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
                    "query": "winlog.event_data.CommandLine.keyword:(*schtasks*\\ \\/delete\\ *Defrag\\\\ScheduledDefrag*)",
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
        "subject": "Sigma Rule 'Defrag Deactivation'",
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
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/958d81aa-8566-4cea-a565-59ccd4df27b0-2 <<EOF
{
  "metadata": {
    "title": "Defrag Deactivation",
    "description": "Detects the deactivation of the Scheduled defragmentation task as seen by Slingshot APT group",
    "tags": [
      "attack.persistence",
      "attack.t1053",
      "attack.s0111"
    ],
    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"4701\" AND TaskName:\"\\\\Microsoft\\\\Windows\\\\Defrag\\\\ScheduledDefrag\")"
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
                    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"4701\" AND TaskName:\"\\\\Microsoft\\\\Windows\\\\Defrag\\\\ScheduledDefrag\")",
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
        "subject": "Sigma Rule 'Defrag Deactivation'",
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
CommandLine.keyword:(*schtasks* \/delete *Defrag\\ScheduledDefrag*)
(EventID:"4701" AND TaskName:"\\Microsoft\\Windows\\Defrag\\ScheduledDefrag")
```


### splunk
    
```
(CommandLine="*schtasks* /delete *Defrag\\ScheduledDefrag*")
(source="WinEventLog:Security" EventCode="4701" TaskName="\\Microsoft\\Windows\\Defrag\\ScheduledDefrag")
```


### logpoint
    
```
(event_id="1" CommandLine IN ["*schtasks* /delete *Defrag\\ScheduledDefrag*"])
(event_source="Microsoft-Windows-Security-Auditing" event_id="4701" TaskName="\\Microsoft\\Windows\\Defrag\\ScheduledDefrag")
```


### grep
    
```
grep -P '^(?:.*.*schtasks.* /delete .*Defrag\ScheduledDefrag.*)'
grep -P '^(?:.*(?=.*4701)(?=.*\Microsoft\Windows\Defrag\ScheduledDefrag))'
```



