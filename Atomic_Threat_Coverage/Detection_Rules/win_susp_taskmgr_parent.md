| Title                    | Taskmgr as Parent       |
|:-------------------------|:------------------|
| **Description**          | Detects the creation of a process from Windows task manager |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1036: Masquerading](https://attack.mitre.org/techniques/T1036)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | low |
| **False Positives**      | <ul><li>Administrative activity</li></ul>  |
| **Development Status**   | experimental |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Taskmgr as Parent
id: 3d7679bd-0c00-440c-97b0-3f204273e6c7
status: experimental
description: Detects the creation of a process from Windows task manager
tags:
    - attack.defense_evasion
    - attack.t1036
author: Florian Roth
date: 2018/03/13
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage: '*\taskmgr.exe'
    filter:
        Image:
            - '*\resmon.exe'
            - '*\mmc.exe'
            - '*\taskmgr.exe'
    condition: selection and not filter
fields:
    - Image
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Administrative activity
level: low

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "ParentImage.*.*\\taskmgr.exe" -and  -not (($_.message -match "Image.*.*\\resmon.exe" -or $_.message -match "Image.*.*\\mmc.exe" -or $_.message -match "Image.*.*\\taskmgr.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.ParentImage.keyword:*\\taskmgr.exe AND (NOT (winlog.event_data.Image.keyword:(*\\resmon.exe OR *\\mmc.exe OR *\\taskmgr.exe))))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/3d7679bd-0c00-440c-97b0-3f204273e6c7 <<EOF
{
  "metadata": {
    "title": "Taskmgr as Parent",
    "description": "Detects the creation of a process from Windows task manager",
    "tags": [
      "attack.defense_evasion",
      "attack.t1036"
    ],
    "query": "(winlog.event_data.ParentImage.keyword:*\\\\taskmgr.exe AND (NOT (winlog.event_data.Image.keyword:(*\\\\resmon.exe OR *\\\\mmc.exe OR *\\\\taskmgr.exe))))"
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
                    "query": "(winlog.event_data.ParentImage.keyword:*\\\\taskmgr.exe AND (NOT (winlog.event_data.Image.keyword:(*\\\\resmon.exe OR *\\\\mmc.exe OR *\\\\taskmgr.exe))))",
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
        "subject": "Sigma Rule 'Taskmgr as Parent'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\n            Image = {{_source.Image}}\n      CommandLine = {{_source.CommandLine}}\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
(ParentImage.keyword:*\\taskmgr.exe AND (NOT (Image.keyword:(*\\resmon.exe *\\mmc.exe *\\taskmgr.exe))))
```


### splunk
    
```
(ParentImage="*\\taskmgr.exe" NOT ((Image="*\\resmon.exe" OR Image="*\\mmc.exe" OR Image="*\\taskmgr.exe"))) | table Image,CommandLine,ParentCommandLine
```


### logpoint
    
```
(event_id="1" ParentImage="*\\taskmgr.exe"  -(Image IN ["*\\resmon.exe", "*\\mmc.exe", "*\\taskmgr.exe"]))
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\taskmgr\.exe)(?=.*(?!.*(?:.*(?=.*(?:.*.*\resmon\.exe|.*.*\mmc\.exe|.*.*\taskmgr\.exe))))))'
```



