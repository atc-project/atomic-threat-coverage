| Title                    | Taskmgr as LOCAL_SYSTEM       |
|:-------------------------|:------------------|
| **Description**          | Detects the creation of taskmgr.exe process in context of LOCAL_SYSTEM |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1036: Masquerading](https://attack.mitre.org/techniques/T1036)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unkown</li></ul>  |
| **Development Status**   | experimental |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Taskmgr as LOCAL_SYSTEM
id: 9fff585c-c33e-4a86-b3cd-39312079a65f
status: experimental
description: Detects the creation of taskmgr.exe process in context of LOCAL_SYSTEM
tags:
    - attack.defense_evasion
    - attack.t1036
author: Florian Roth
date: 2018/03/18
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        User: NT AUTHORITY\SYSTEM
        Image: '*\taskmgr.exe'
    condition: selection
falsepositives:
    - Unkown
level: high

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "User.*NT AUTHORITY\\SYSTEM" -and $_.message -match "Image.*.*\\taskmgr.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.User:"NT\ AUTHORITY\\SYSTEM" AND winlog.event_data.Image.keyword:*\\taskmgr.exe)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/9fff585c-c33e-4a86-b3cd-39312079a65f <<EOF
{
  "metadata": {
    "title": "Taskmgr as LOCAL_SYSTEM",
    "description": "Detects the creation of taskmgr.exe process in context of LOCAL_SYSTEM",
    "tags": [
      "attack.defense_evasion",
      "attack.t1036"
    ],
    "query": "(winlog.event_data.User:\"NT\\ AUTHORITY\\\\SYSTEM\" AND winlog.event_data.Image.keyword:*\\\\taskmgr.exe)"
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
                    "query": "(winlog.event_data.User:\"NT\\ AUTHORITY\\\\SYSTEM\" AND winlog.event_data.Image.keyword:*\\\\taskmgr.exe)",
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
        "subject": "Sigma Rule 'Taskmgr as LOCAL_SYSTEM'",
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
(User:"NT AUTHORITY\\SYSTEM" AND Image.keyword:*\\taskmgr.exe)
```


### splunk
    
```
(User="NT AUTHORITY\\SYSTEM" Image="*\\taskmgr.exe")
```


### logpoint
    
```
(User="NT AUTHORITY\\SYSTEM" Image="*\\taskmgr.exe")
```


### grep
    
```
grep -P '^(?:.*(?=.*NT AUTHORITY\SYSTEM)(?=.*.*\taskmgr\.exe))'
```



