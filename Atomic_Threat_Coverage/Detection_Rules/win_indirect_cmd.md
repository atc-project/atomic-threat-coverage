| Title                    | Indirect Command Execution       |
|:-------------------------|:------------------|
| **Description**          | Detect indirect command execution via Program Compatibility Assistant pcalua.exe or forfiles.exe |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1202: Indirect Command Execution](https://attack.mitre.org/techniques/T1202)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1202: Indirect Command Execution](../Triggers/T1202.md)</li></ul>  |
| **Severity Level**       | low |
| **False Positives**      | <ul><li>Need to use extra processing with 'unique_count' / 'filter' to focus on outliers as opposed to commonly seen artifacts</li><li>Legit usage of scripts</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1202/T1202.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1202/T1202.yaml)</li><li>[https://eqllib.readthedocs.io/en/latest/analytics/884a7ccd-7305-4130-82d0-d4f90bc118b6.html](https://eqllib.readthedocs.io/en/latest/analytics/884a7ccd-7305-4130-82d0-d4f90bc118b6.html)</li></ul>  |
| **Author**               | E.M. Anhaus (orignally from Atomic Blue Detections, Endgame), oscd.community |


## Detection Rules

### Sigma rule

```
title: Indirect Command Execution
id: fa47597e-90e9-41cd-ab72-c3b74cfb0d02
description: Detect indirect command execution via Program Compatibility Assistant pcalua.exe or forfiles.exe
status: experimental
author: E.M. Anhaus (orignally from Atomic Blue Detections, Endgame), oscd.community
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1202/T1202.yaml
    - https://eqllib.readthedocs.io/en/latest/analytics/884a7ccd-7305-4130-82d0-d4f90bc118b6.html
date: 2019/10/24
modified: 2019/11/11
tags:
    - attack.defense_evasion
    - attack.t1202
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith:
            - '\pcalua.exe'
            - '\forfiles.exe'
    condition: selection
fields:
    - ComputerName
    - User
    - ParentCommandLine
    - CommandLine
falsepositives:
    - Need to use extra processing with 'unique_count' / 'filter' to focus on outliers as opposed to commonly seen artifacts
    - Legit usage of scripts
level: low

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "ParentImage.*.*\\pcalua.exe" -or $_.message -match "ParentImage.*.*\\forfiles.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.ParentImage.keyword:(*\\pcalua.exe OR *\\forfiles.exe)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/fa47597e-90e9-41cd-ab72-c3b74cfb0d02 <<EOF
{
  "metadata": {
    "title": "Indirect Command Execution",
    "description": "Detect indirect command execution via Program Compatibility Assistant pcalua.exe or forfiles.exe",
    "tags": [
      "attack.defense_evasion",
      "attack.t1202"
    ],
    "query": "winlog.event_data.ParentImage.keyword:(*\\\\pcalua.exe OR *\\\\forfiles.exe)"
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
                    "query": "winlog.event_data.ParentImage.keyword:(*\\\\pcalua.exe OR *\\\\forfiles.exe)",
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
        "subject": "Sigma Rule 'Indirect Command Execution'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\n     ComputerName = {{_source.ComputerName}}\n             User = {{_source.User}}\nParentCommandLine = {{_source.ParentCommandLine}}\n      CommandLine = {{_source.CommandLine}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
ParentImage.keyword:(*\\pcalua.exe *\\forfiles.exe)
```


### splunk
    
```
(ParentImage="*\\pcalua.exe" OR ParentImage="*\\forfiles.exe") | table ComputerName,User,ParentCommandLine,CommandLine
```


### logpoint
    
```
(event_id="1" ParentImage IN ["*\\pcalua.exe", "*\\forfiles.exe"])
```


### grep
    
```
grep -P '^(?:.*.*\pcalua\.exe|.*.*\forfiles\.exe)'
```



