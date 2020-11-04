| Title                    | Suspicious Bitsadmin Job via PowerShell       |
|:-------------------------|:------------------|
| **Description**          | Detect download by BITS jobs via PowerShell |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1197: BITS Jobs](https://attack.mitre.org/techniques/T1197)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1197: BITS Jobs](../Triggers/T1197.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://eqllib.readthedocs.io/en/latest/analytics/ec5180c9-721a-460f-bddc-27539a284273.html](https://eqllib.readthedocs.io/en/latest/analytics/ec5180c9-721a-460f-bddc-27539a284273.html)</li><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1197/T1197.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1197/T1197.md)</li></ul>  |
| **Author**               | Endgame, JHasenbusch (ported to sigma for oscd.community) |


## Detection Rules

### Sigma rule

```
title: Suspicious Bitsadmin Job via PowerShell
id: f67dbfce-93bc-440d-86ad-a95ae8858c90
status: experimental
description: Detect download by BITS jobs via PowerShell
references:
    - https://eqllib.readthedocs.io/en/latest/analytics/ec5180c9-721a-460f-bddc-27539a284273.html
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1197/T1197.md
author: Endgame, JHasenbusch (ported to sigma for oscd.community)
date: 2018/10/30
modified: 2019/11/11
tags:
    - attack.defense_evasion
    - attack.persistence
    - attack.t1197
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains: 'Start-BitsTransfer'
    condition: selection
fields:
    - ComputerName
    - User
    - CommandLine
falsepositives:
    - Unknown
level: medium

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "Image.*.*\\powershell.exe" -and $_.message -match "CommandLine.*.*Start-BitsTransfer.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:*\\powershell.exe AND winlog.event_data.CommandLine.keyword:*Start\-BitsTransfer*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/f67dbfce-93bc-440d-86ad-a95ae8858c90 <<EOF
{
  "metadata": {
    "title": "Suspicious Bitsadmin Job via PowerShell",
    "description": "Detect download by BITS jobs via PowerShell",
    "tags": [
      "attack.defense_evasion",
      "attack.persistence",
      "attack.t1197"
    ],
    "query": "(winlog.event_data.Image.keyword:*\\\\powershell.exe AND winlog.event_data.CommandLine.keyword:*Start\\-BitsTransfer*)"
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
                    "query": "(winlog.event_data.Image.keyword:*\\\\powershell.exe AND winlog.event_data.CommandLine.keyword:*Start\\-BitsTransfer*)",
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
      "email": {
        "to": "root@localhost",
        "subject": "Sigma Rule 'Suspicious Bitsadmin Job via PowerShell'",
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
(Image.keyword:*\\powershell.exe AND CommandLine.keyword:*Start\-BitsTransfer*)
```


### splunk
    
```
(Image="*\\powershell.exe" CommandLine="*Start-BitsTransfer*") | table ComputerName,User,CommandLine
```


### logpoint
    
```
(Image="*\\powershell.exe" CommandLine="*Start-BitsTransfer*")
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\powershell\.exe)(?=.*.*Start-BitsTransfer.*))'
```



