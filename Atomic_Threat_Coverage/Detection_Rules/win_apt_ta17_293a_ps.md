| Title                    | Ps.exe Renamed SysInternals Tool       |
|:-------------------------|:------------------|
| **Description**          | Detects renamed SysInternals tool execution with a binary named ps.exe as used by Dragonfly APT group and documented in TA17-293A report |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1036: Masquerading](https://attack.mitre.org/techniques/T1036)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Renamed SysInternals tool</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://www.us-cert.gov/ncas/alerts/TA17-293A](https://www.us-cert.gov/ncas/alerts/TA17-293A)</li></ul>  |
| **Author**               | Florian Roth |
| Other Tags           | <ul><li>attack.g0035</li><li>car.2013-05-009</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Ps.exe Renamed SysInternals Tool
id: 18da1007-3f26-470f-875d-f77faf1cab31
description: Detects renamed SysInternals tool execution with a binary named ps.exe as used by Dragonfly APT group and documented in TA17-293A report
references:
    - https://www.us-cert.gov/ncas/alerts/TA17-293A
tags:
    - attack.defense_evasion
    - attack.g0035
    - attack.t1036
    - car.2013-05-009
author: Florian Roth
date: 2017/10/22
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine: 'ps.exe -accepteula'
    condition: selection
falsepositives:
    - Renamed SysInternals tool
level: high
```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "CommandLine.*ps.exe -accepteula") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.CommandLine:"ps.exe\ \-accepteula"
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/18da1007-3f26-470f-875d-f77faf1cab31 <<EOF
{
  "metadata": {
    "title": "Ps.exe Renamed SysInternals Tool",
    "description": "Detects renamed SysInternals tool execution with a binary named ps.exe as used by Dragonfly APT group and documented in TA17-293A report",
    "tags": [
      "attack.defense_evasion",
      "attack.g0035",
      "attack.t1036",
      "car.2013-05-009"
    ],
    "query": "winlog.event_data.CommandLine:\"ps.exe\\ \\-accepteula\""
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
                    "query": "winlog.event_data.CommandLine:\"ps.exe\\ \\-accepteula\"",
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
        "subject": "Sigma Rule 'Ps.exe Renamed SysInternals Tool'",
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
CommandLine:"ps.exe \-accepteula"
```


### splunk
    
```
CommandLine="ps.exe -accepteula"
```


### logpoint
    
```
(event_id="1" CommandLine="ps.exe -accepteula")
```


### grep
    
```
grep -P '^ps\.exe -accepteula'
```



