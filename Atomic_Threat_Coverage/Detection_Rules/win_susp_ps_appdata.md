| Title                    | PowerShell Script Run in AppData       |
|:-------------------------|:------------------|
| **Description**          | Detects a suspicious command line execution that invokes PowerShell with reference to an AppData folder |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Administrative scripts</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://twitter.com/JohnLaTwC/status/1082851155481288706](https://twitter.com/JohnLaTwC/status/1082851155481288706)</li><li>[https://app.any.run/tasks/f87f1c4e-47e2-4c46-9cf4-31454c06ce03](https://app.any.run/tasks/f87f1c4e-47e2-4c46-9cf4-31454c06ce03)</li></ul>  |
| **Author**               | Florian Roth |
| Other Tags           | <ul><li>attack.t1059.001</li></ul> | 

## Detection Rules

### Sigma rule

```
title: PowerShell Script Run in AppData
id: ac175779-025a-4f12-98b0-acdaeb77ea85
status: experimental
description: Detects a suspicious command line execution that invokes PowerShell with reference to an AppData folder
references:
    - https://twitter.com/JohnLaTwC/status/1082851155481288706
    - https://app.any.run/tasks/f87f1c4e-47e2-4c46-9cf4-31454c06ce03
tags:
    - attack.execution
    - attack.t1086
    - attack.t1059.001
author: Florian Roth
date: 2019/01/09
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - '* /c powershell*\AppData\Local\\*'
            - '* /c powershell*\AppData\Roaming\\*'
    condition: selection
falsepositives:
    - Administrative scripts
level: medium

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.* /c powershell.*\\AppData\\Local\\.*" -or $_.message -match "CommandLine.*.* /c powershell.*\\AppData\\Roaming\\.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.CommandLine.keyword:(*\ \/c\ powershell*\\AppData\\Local\\* OR *\ \/c\ powershell*\\AppData\\Roaming\\*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/ac175779-025a-4f12-98b0-acdaeb77ea85 <<EOF
{
  "metadata": {
    "title": "PowerShell Script Run in AppData",
    "description": "Detects a suspicious command line execution that invokes PowerShell with reference to an AppData folder",
    "tags": [
      "attack.execution",
      "attack.t1086",
      "attack.t1059.001"
    ],
    "query": "winlog.event_data.CommandLine.keyword:(*\\ \\/c\\ powershell*\\\\AppData\\\\Local\\\\* OR *\\ \\/c\\ powershell*\\\\AppData\\\\Roaming\\\\*)"
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
                    "query": "winlog.event_data.CommandLine.keyword:(*\\ \\/c\\ powershell*\\\\AppData\\\\Local\\\\* OR *\\ \\/c\\ powershell*\\\\AppData\\\\Roaming\\\\*)",
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
        "subject": "Sigma Rule 'PowerShell Script Run in AppData'",
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
CommandLine.keyword:(* \/c powershell*\\AppData\\Local\\* * \/c powershell*\\AppData\\Roaming\\*)
```


### splunk
    
```
(CommandLine="* /c powershell*\\AppData\\Local\\*" OR CommandLine="* /c powershell*\\AppData\\Roaming\\*")
```


### logpoint
    
```
(event_id="1" CommandLine IN ["* /c powershell*\\AppData\\Local\\*", "* /c powershell*\\AppData\\Roaming\\*"])
```


### grep
    
```
grep -P '^(?:.*.* /c powershell.*\AppData\Local\\.*|.*.* /c powershell.*\AppData\Roaming\\.*)'
```



