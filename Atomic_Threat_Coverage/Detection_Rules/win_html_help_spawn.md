| Title                    | HTML Help Shell Spawn       |
|:-------------------------|:------------------|
| **Description**          | Detects a suspicious child process of a Microsoft HTML Help system when executing compiled HTML files (.chm) |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1223: Compiled HTML File](https://attack.mitre.org/techniques/T1223)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1223: Compiled HTML File](../Triggers/T1223.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/chm-badness-delivers-a-banking-trojan/](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/chm-badness-delivers-a-banking-trojan/)</li></ul>  |
| **Author**               | Maxim Pavlunin |


## Detection Rules

### Sigma rule

```
title: HTML Help Shell Spawn
id: 52cad028-0ff0-4854-8f67-d25dfcbc78b4
status: experimental
description: Detects a suspicious child process of a Microsoft HTML Help system when executing compiled HTML files (.chm)
references:
    - https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/chm-badness-delivers-a-banking-trojan/
author: Maxim Pavlunin
date: 2020/04/01
modified: 2020/04/03
tags:
    - attack.execution
    - attack.defense_evasion
    - attack.t1223
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage: 'C:\Windows\hh.exe'
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\wscript.exe'
            - '\cscript.exe'
            - '\regsvr32.exe'
            - '\wmic.exe'
            - '\rundll32.exe'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - unknown
level: high

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "ParentImage.*C:\\Windows\\hh.exe" -and ($_.message -match "Image.*.*\\cmd.exe" -or $_.message -match "Image.*.*\\powershell.exe" -or $_.message -match "Image.*.*\\wscript.exe" -or $_.message -match "Image.*.*\\cscript.exe" -or $_.message -match "Image.*.*\\regsvr32.exe" -or $_.message -match "Image.*.*\\wmic.exe" -or $_.message -match "Image.*.*\\rundll32.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.ParentImage:"C\:\\Windows\\hh.exe" AND winlog.event_data.Image.keyword:(*\\cmd.exe OR *\\powershell.exe OR *\\wscript.exe OR *\\cscript.exe OR *\\regsvr32.exe OR *\\wmic.exe OR *\\rundll32.exe))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/52cad028-0ff0-4854-8f67-d25dfcbc78b4 <<EOF
{
  "metadata": {
    "title": "HTML Help Shell Spawn",
    "description": "Detects a suspicious child process of a Microsoft HTML Help system when executing compiled HTML files (.chm)",
    "tags": [
      "attack.execution",
      "attack.defense_evasion",
      "attack.t1223"
    ],
    "query": "(winlog.event_data.ParentImage:\"C\\:\\\\Windows\\\\hh.exe\" AND winlog.event_data.Image.keyword:(*\\\\cmd.exe OR *\\\\powershell.exe OR *\\\\wscript.exe OR *\\\\cscript.exe OR *\\\\regsvr32.exe OR *\\\\wmic.exe OR *\\\\rundll32.exe))"
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
                    "query": "(winlog.event_data.ParentImage:\"C\\:\\\\Windows\\\\hh.exe\" AND winlog.event_data.Image.keyword:(*\\\\cmd.exe OR *\\\\powershell.exe OR *\\\\wscript.exe OR *\\\\cscript.exe OR *\\\\regsvr32.exe OR *\\\\wmic.exe OR *\\\\rundll32.exe))",
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
        "subject": "Sigma Rule 'HTML Help Shell Spawn'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\n      CommandLine = {{_source.CommandLine}}\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
(ParentImage:"C\:\\Windows\\hh.exe" AND Image.keyword:(*\\cmd.exe *\\powershell.exe *\\wscript.exe *\\cscript.exe *\\regsvr32.exe *\\wmic.exe *\\rundll32.exe))
```


### splunk
    
```
(ParentImage="C:\\Windows\\hh.exe" (Image="*\\cmd.exe" OR Image="*\\powershell.exe" OR Image="*\\wscript.exe" OR Image="*\\cscript.exe" OR Image="*\\regsvr32.exe" OR Image="*\\wmic.exe" OR Image="*\\rundll32.exe")) | table CommandLine,ParentCommandLine
```


### logpoint
    
```
(ParentImage="C:\\Windows\\hh.exe" Image IN ["*\\cmd.exe", "*\\powershell.exe", "*\\wscript.exe", "*\\cscript.exe", "*\\regsvr32.exe", "*\\wmic.exe", "*\\rundll32.exe"])
```


### grep
    
```
grep -P '^(?:.*(?=.*C:\Windows\hh\.exe)(?=.*(?:.*.*\cmd\.exe|.*.*\powershell\.exe|.*.*\wscript\.exe|.*.*\cscript\.exe|.*.*\regsvr32\.exe|.*.*\wmic\.exe|.*.*\rundll32\.exe)))'
```



