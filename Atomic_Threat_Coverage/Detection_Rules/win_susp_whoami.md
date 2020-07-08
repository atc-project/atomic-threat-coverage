| Title                    | Whoami Execution       |
|:-------------------------|:------------------|
| **Description**          | Detects the execution of whoami, which is often used by attackers after exloitation / privilege escalation but rarely used by administrators |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1033: System Owner/User Discovery](https://attack.mitre.org/techniques/T1033)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1033: System Owner/User Discovery](../Triggers/T1033.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Admin activity</li><li>Scripts and administrative tools used in the monitored environment</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://brica.de/alerts/alert/public/1247926/agent-tesla-keylogger-delivered-inside-a-power-iso-daa-archive/](https://brica.de/alerts/alert/public/1247926/agent-tesla-keylogger-delivered-inside-a-power-iso-daa-archive/)</li><li>[https://app.any.run/tasks/7eaba74e-c1ea-400f-9c17-5e30eee89906/](https://app.any.run/tasks/7eaba74e-c1ea-400f-9c17-5e30eee89906/)</li></ul>  |
| **Author**               | Florian Roth |
| Other Tags           | <ul><li>car.2016-03-001</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Whoami Execution
id: e28a5a99-da44-436d-b7a0-2afc20a5f413
status: experimental
description: Detects the execution of whoami, which is often used by attackers after exloitation / privilege escalation but rarely used by administrators
references:
    - https://brica.de/alerts/alert/public/1247926/agent-tesla-keylogger-delivered-inside-a-power-iso-daa-archive/
    - https://app.any.run/tasks/7eaba74e-c1ea-400f-9c17-5e30eee89906/
author: Florian Roth
date: 2018/08/13
tags:
    - attack.discovery
    - attack.t1033
    - car.2016-03-001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: '*\whoami.exe'
    selection2:
        OriginalFileName: 'whoami.exe'
    condition: selection or selection2
falsepositives:
    - Admin activity
    - Scripts and administrative tools used in the monitored environment
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ($_.message -match "Image.*.*\\whoami.exe" -or $_.message -match "OriginalFileName.*whoami.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:*\\whoami.exe OR OriginalFileName:"whoami.exe")
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/e28a5a99-da44-436d-b7a0-2afc20a5f413 <<EOF
{
  "metadata": {
    "title": "Whoami Execution",
    "description": "Detects the execution of whoami, which is often used by attackers after exloitation / privilege escalation but rarely used by administrators",
    "tags": [
      "attack.discovery",
      "attack.t1033",
      "car.2016-03-001"
    ],
    "query": "(winlog.event_data.Image.keyword:*\\\\whoami.exe OR OriginalFileName:\"whoami.exe\")"
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
                    "query": "(winlog.event_data.Image.keyword:*\\\\whoami.exe OR OriginalFileName:\"whoami.exe\")",
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
        "subject": "Sigma Rule 'Whoami Execution'",
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
(Image.keyword:*\\whoami.exe OR OriginalFileName:"whoami.exe")
```


### splunk
    
```
(Image="*\\whoami.exe" OR OriginalFileName="whoami.exe")
```


### logpoint
    
```
(event_id="1" (Image="*\\whoami.exe" OR OriginalFileName="whoami.exe"))
```


### grep
    
```
grep -P '^(?:.*(?:.*.*\whoami\.exe|.*whoami\.exe))'
```



