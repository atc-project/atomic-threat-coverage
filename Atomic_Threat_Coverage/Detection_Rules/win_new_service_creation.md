| Title                    | New Service Creation       |
|:-------------------------|:------------------|
| **Description**          | Detects creation if a new service |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1050: New Service](https://attack.mitre.org/techniques/T1050)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | low |
| **False Positives**      | <ul><li>Legitimate administrator or user creates a service for legitimate reason</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1050/T1050.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1050/T1050.yaml)</li></ul>  |
| **Author**               | Timur Zinniatullin, Daniil Yugoslavskiy, oscd.community |
| Other Tags           | <ul><li>attack.t1543.003</li></ul> | 

## Detection Rules

### Sigma rule

```
title: New Service Creation
id: 7fe71fc9-de3b-432a-8d57-8c809efc10ab
status: experimental
description: Detects creation if a new service
author: Timur Zinniatullin, Daniil Yugoslavskiy, oscd.community
date: 2019/10/21
modified: 2019/11/04
tags:
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1050
    - attack.t1543.003
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1050/T1050.yaml
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\sc.exe'
          CommandLine|contains|all:
            - 'create'
            - 'binpath'
        - Image|endswith: '\powershell.exe'
          CommandLine|contains: 'new-service'
    condition: selection
falsepositives:
    - Legitimate administrator or user creates a service for legitimate reason
level: low

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "Image.*.*\\sc.exe" -and $_.message -match "CommandLine.*.*create.*" -and $_.message -match "CommandLine.*.*binpath.*") -or ($_.message -match "Image.*.*\\powershell.exe" -and $_.message -match "CommandLine.*.*new-service.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
((winlog.event_data.Image.keyword:*\\sc.exe AND winlog.event_data.CommandLine.keyword:*create* AND winlog.event_data.CommandLine.keyword:*binpath*) OR (winlog.event_data.Image.keyword:*\\powershell.exe AND winlog.event_data.CommandLine.keyword:*new\-service*))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/7fe71fc9-de3b-432a-8d57-8c809efc10ab <<EOF
{
  "metadata": {
    "title": "New Service Creation",
    "description": "Detects creation if a new service",
    "tags": [
      "attack.persistence",
      "attack.privilege_escalation",
      "attack.t1050",
      "attack.t1543.003"
    ],
    "query": "((winlog.event_data.Image.keyword:*\\\\sc.exe AND winlog.event_data.CommandLine.keyword:*create* AND winlog.event_data.CommandLine.keyword:*binpath*) OR (winlog.event_data.Image.keyword:*\\\\powershell.exe AND winlog.event_data.CommandLine.keyword:*new\\-service*))"
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
                    "query": "((winlog.event_data.Image.keyword:*\\\\sc.exe AND winlog.event_data.CommandLine.keyword:*create* AND winlog.event_data.CommandLine.keyword:*binpath*) OR (winlog.event_data.Image.keyword:*\\\\powershell.exe AND winlog.event_data.CommandLine.keyword:*new\\-service*))",
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
        "subject": "Sigma Rule 'New Service Creation'",
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
((Image.keyword:*\\sc.exe AND CommandLine.keyword:*create* AND CommandLine.keyword:*binpath*) OR (Image.keyword:*\\powershell.exe AND CommandLine.keyword:*new\-service*))
```


### splunk
    
```
((Image="*\\sc.exe" CommandLine="*create*" CommandLine="*binpath*") OR (Image="*\\powershell.exe" CommandLine="*new-service*"))
```


### logpoint
    
```
(event_id="1" ((Image="*\\sc.exe" CommandLine="*create*" CommandLine="*binpath*") OR (Image="*\\powershell.exe" CommandLine="*new-service*")))
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*(?=.*.*\sc\.exe)(?=.*.*create.*)(?=.*.*binpath.*))|.*(?:.*(?=.*.*\powershell\.exe)(?=.*.*new-service.*))))'
```



