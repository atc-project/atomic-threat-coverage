| Title                    | Interactive AT Job       |
|:-------------------------|:------------------|
| **Description**          | Detect an interactive AT job, which may be used as a form of privilege escalation |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1053: Scheduled Task/Job](https://attack.mitre.org/techniques/T1053)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unlikely (at.exe deprecated as of Windows 8)</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053/T1053.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053/T1053.yaml)</li><li>[https://eqllib.readthedocs.io/en/latest/analytics/d8db43cf-ed52-4f5c-9fb3-c9a4b95a0b56.html](https://eqllib.readthedocs.io/en/latest/analytics/d8db43cf-ed52-4f5c-9fb3-c9a4b95a0b56.html)</li></ul>  |
| **Author**               | E.M. Anhaus (orignally from Atomic Blue Detections, Endgame), oscd.community |
| Other Tags           | <ul><li>attack.t1053.002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Interactive AT Job
id: 60fc936d-2eb0-4543-8a13-911c750a1dfc
description: Detect an interactive AT job, which may be used as a form of privilege escalation
status: experimental
author: E.M. Anhaus (orignally from Atomic Blue Detections, Endgame), oscd.community
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053/T1053.yaml
    - https://eqllib.readthedocs.io/en/latest/analytics/d8db43cf-ed52-4f5c-9fb3-c9a4b95a0b56.html
date: 2019/10/24
modified: 2019/11/11
tags:
    - attack.privilege_escalation
    - attack.t1053
    - attack.t1053.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\at.exe'
        CommandLine|contains: 'interactive'
    condition: selection
fields:
    - ComputerName
    - User
    - CommandLine
falsepositives:
    - Unlikely (at.exe deprecated as of Windows 8)
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\\at.exe" -and $_.message -match "CommandLine.*.*interactive.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:*\\at.exe AND winlog.event_data.CommandLine.keyword:*interactive*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/60fc936d-2eb0-4543-8a13-911c750a1dfc <<EOF
{
  "metadata": {
    "title": "Interactive AT Job",
    "description": "Detect an interactive AT job, which may be used as a form of privilege escalation",
    "tags": [
      "attack.privilege_escalation",
      "attack.t1053",
      "attack.t1053.002"
    ],
    "query": "(winlog.event_data.Image.keyword:*\\\\at.exe AND winlog.event_data.CommandLine.keyword:*interactive*)"
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
                    "query": "(winlog.event_data.Image.keyword:*\\\\at.exe AND winlog.event_data.CommandLine.keyword:*interactive*)",
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
        "subject": "Sigma Rule 'Interactive AT Job'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\nComputerName = {{_source.ComputerName}}\n        User = {{_source.User}}\n CommandLine = {{_source.CommandLine}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
(Image.keyword:*\\at.exe AND CommandLine.keyword:*interactive*)
```


### splunk
    
```
(Image="*\\at.exe" CommandLine="*interactive*") | table ComputerName,User,CommandLine
```


### logpoint
    
```
(event_id="1" Image="*\\at.exe" CommandLine="*interactive*")
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\at\.exe)(?=.*.*interactive.*))'
```



