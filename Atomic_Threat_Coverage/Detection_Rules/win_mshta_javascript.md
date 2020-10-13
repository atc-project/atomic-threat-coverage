| Title                    | Mshta JavaScript Execution       |
|:-------------------------|:------------------|
| **Description**          | Identifies suspicious mshta.exe commands |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1170: Mshta](https://attack.mitre.org/techniques/T1170)</li><li>[T1218.005: Mshta](https://attack.mitre.org/techniques/T1218/005)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1218.005: Mshta](../Triggers/T1218.005.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://eqllib.readthedocs.io/en/latest/analytics/6bc283c4-21f2-4aed-a05c-a9a3ffa95dd4.html](https://eqllib.readthedocs.io/en/latest/analytics/6bc283c4-21f2-4aed-a05c-a9a3ffa95dd4.html)</li><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1170/T1170.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1170/T1170.yaml)</li></ul>  |
| **Author**               | E.M. Anhaus (orignally from Atomic Blue Detections, Endgame), oscd.community |


## Detection Rules

### Sigma rule

```
title: Mshta JavaScript Execution
id: 67f113fa-e23d-4271-befa-30113b3e08b1
description: Identifies suspicious mshta.exe commands
status: experimental
author: E.M. Anhaus (orignally from Atomic Blue Detections, Endgame), oscd.community
date: 2019/10/24
modified: 2020/09/01
references:
    - https://eqllib.readthedocs.io/en/latest/analytics/6bc283c4-21f2-4aed-a05c-a9a3ffa95dd4.html
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1170/T1170.yaml
tags:
    - attack.defense_evasion
    - attack.t1170          # an old one
    - attack.t1218.005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\mshta.exe'
        CommandLine|contains: 'javascript'
    condition: selection
fields:
    - ComputerName
    - User
    - CommandLine
falsepositives:
    - unknown
level: high
## todo — add sysmon eid 3 for this rule

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "Image.*.*\\mshta.exe" -and $_.message -match "CommandLine.*.*javascript.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:*\\mshta.exe AND winlog.event_data.CommandLine.keyword:*javascript*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/67f113fa-e23d-4271-befa-30113b3e08b1 <<EOF
{
  "metadata": {
    "title": "Mshta JavaScript Execution",
    "description": "Identifies suspicious mshta.exe commands",
    "tags": [
      "attack.defense_evasion",
      "attack.t1170",
      "attack.t1218.005"
    ],
    "query": "(winlog.event_data.Image.keyword:*\\\\mshta.exe AND winlog.event_data.CommandLine.keyword:*javascript*)"
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
                    "query": "(winlog.event_data.Image.keyword:*\\\\mshta.exe AND winlog.event_data.CommandLine.keyword:*javascript*)",
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
        "subject": "Sigma Rule 'Mshta JavaScript Execution'",
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
(Image.keyword:*\\mshta.exe AND CommandLine.keyword:*javascript*)
```


### splunk
    
```
(Image="*\\mshta.exe" CommandLine="*javascript*") | table ComputerName,User,CommandLine
```


### logpoint
    
```
(Image="*\\mshta.exe" CommandLine="*javascript*")
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\mshta\.exe)(?=.*.*javascript.*))'
```



