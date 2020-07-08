| Title                    | Suspicious Calculator Usage       |
|:-------------------------|:------------------|
| **Description**          | Detects suspicious use of calc.exe with command line parameters or in a suspicious directory, which is likely caused by some PoC or detection evasion |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1036: Masquerading](https://attack.mitre.org/techniques/T1036)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://twitter.com/ItsReallyNick/status/1094080242686312448](https://twitter.com/ItsReallyNick/status/1094080242686312448)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Suspicious Calculator Usage
id: 737e618a-a410-49b5-bec3-9e55ff7fbc15
description: Detects suspicious use of calc.exe with command line parameters or in a suspicious directory, which is likely caused by some PoC or detection evasion
status: experimental
references:
    - https://twitter.com/ItsReallyNick/status/1094080242686312448
author: Florian Roth
date: 2019/02/09
tags:
    - attack.defense_evasion
    - attack.t1036
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine: '*\calc.exe *'
    selection2:
        Image: '*\calc.exe'
    filter2:
        Image: '*\Windows\Sys*'
    condition: selection1 or ( selection2 and not filter2 )
falsepositives:
    - Unknown
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ($_.message -match "CommandLine.*.*\\calc.exe .*" -or ($_.ID -eq "1" -and $_.message -match "Image.*.*\\calc.exe" -and  -not ($_.message -match "Image.*.*\\Windows\\Sys.*")))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.CommandLine.keyword:*\\calc.exe\ * OR (winlog.event_data.Image.keyword:*\\calc.exe AND (NOT (winlog.event_data.Image.keyword:*\\Windows\\Sys*))))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/737e618a-a410-49b5-bec3-9e55ff7fbc15 <<EOF
{
  "metadata": {
    "title": "Suspicious Calculator Usage",
    "description": "Detects suspicious use of calc.exe with command line parameters or in a suspicious directory, which is likely caused by some PoC or detection evasion",
    "tags": [
      "attack.defense_evasion",
      "attack.t1036"
    ],
    "query": "(winlog.event_data.CommandLine.keyword:*\\\\calc.exe\\ * OR (winlog.event_data.Image.keyword:*\\\\calc.exe AND (NOT (winlog.event_data.Image.keyword:*\\\\Windows\\\\Sys*))))"
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
                    "query": "(winlog.event_data.CommandLine.keyword:*\\\\calc.exe\\ * OR (winlog.event_data.Image.keyword:*\\\\calc.exe AND (NOT (winlog.event_data.Image.keyword:*\\\\Windows\\\\Sys*))))",
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
        "subject": "Sigma Rule 'Suspicious Calculator Usage'",
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
(CommandLine.keyword:*\\calc.exe * OR (Image.keyword:*\\calc.exe AND (NOT (Image.keyword:*\\Windows\\Sys*))))
```


### splunk
    
```
(CommandLine="*\\calc.exe *" OR (Image="*\\calc.exe" NOT (Image="*\\Windows\\Sys*")))
```


### logpoint
    
```
(event_id="1" (CommandLine="*\\calc.exe *" OR (event_id="1" Image="*\\calc.exe"  -(Image="*\\Windows\\Sys*"))))
```


### grep
    
```
grep -P '^(?:.*(?:.*.*\calc\.exe .*|.*(?:.*(?=.*.*\calc\.exe)(?=.*(?!.*(?:.*(?=.*.*\Windows\Sys.*)))))))'
```



