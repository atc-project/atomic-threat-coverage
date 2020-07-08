| Title                    | Remote PowerShell Session       |
|:-------------------------|:------------------|
| **Description**          | Detects remote PowerShell sessions |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Legitimate use remote PowerShell sessions</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/02_execution/T1086_powershell/powershell_remote_session.md](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/02_execution/T1086_powershell/powershell_remote_session.md)</li></ul>  |
| **Author**               | Roberto Rodriguez @Cyb3rWard0g |
| Other Tags           | <ul><li>attack.t1059.001</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Remote PowerShell Session
id: 96b9f619-aa91-478f-bacb-c3e50f8df575
description: Detects remote PowerShell sessions
status: experimental
date: 2019/08/10
modified: 2019/11/10
author: Roberto Rodriguez @Cyb3rWard0g
references:
    - https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/02_execution/T1086_powershell/powershell_remote_session.md
tags:
    - attack.execution
    - attack.t1086
    - attack.t1059.001
logsource:
    product: windows
    service: powershell
detection:
    selection:
        EventID:
            - 4103
            - 400
        HostName: 'ServerRemoteHost'
        HostApplication|contains: 'wsmprovhost.exe'
    condition: selection
falsepositives:
    - Legitimate use remote PowerShell sessions
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {(($_.ID -eq "4103" -or $_.ID -eq "400") -and $_.message -match "HostName.*ServerRemoteHost" -and $_.message -match "HostApplication.*.*wsmprovhost.exe.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_id:("4103" OR "400") AND HostName:"ServerRemoteHost" AND HostApplication.keyword:*wsmprovhost.exe*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/96b9f619-aa91-478f-bacb-c3e50f8df575 <<EOF
{
  "metadata": {
    "title": "Remote PowerShell Session",
    "description": "Detects remote PowerShell sessions",
    "tags": [
      "attack.execution",
      "attack.t1086",
      "attack.t1059.001"
    ],
    "query": "(winlog.event_id:(\"4103\" OR \"400\") AND HostName:\"ServerRemoteHost\" AND HostApplication.keyword:*wsmprovhost.exe*)"
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
                    "query": "(winlog.event_id:(\"4103\" OR \"400\") AND HostName:\"ServerRemoteHost\" AND HostApplication.keyword:*wsmprovhost.exe*)",
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
        "subject": "Sigma Rule 'Remote PowerShell Session'",
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
(EventID:("4103" "400") AND HostName:"ServerRemoteHost" AND HostApplication.keyword:*wsmprovhost.exe*)
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-PowerShell/Operational" (EventCode="4103" OR EventCode="400") HostName="ServerRemoteHost" HostApplication="*wsmprovhost.exe*")
```


### logpoint
    
```
(event_id IN ["4103", "400"] HostName="ServerRemoteHost" HostApplication="*wsmprovhost.exe*")
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*4103|.*400))(?=.*ServerRemoteHost)(?=.*.*wsmprovhost\.exe.*))'
```



