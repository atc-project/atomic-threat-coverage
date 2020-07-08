| Title                    | MS Office Product Spawning Exe in User Dir       |
|:-------------------------|:------------------|
| **Description**          | Detects an executable in the users directory started from Microsoft Word, Excel, Powerpoint, Publisher or Visio |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1059: Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059)</li><li>[T1202: Indirect Command Execution](https://attack.mitre.org/techniques/T1202)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1202: Indirect Command Execution](../Triggers/T1202.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[sha256=23160972c6ae07f740800fa28e421a81d7c0ca5d5cab95bc082b4a986fbac57c](sha256=23160972c6ae07f740800fa28e421a81d7c0ca5d5cab95bc082b4a986fbac57c)</li><li>[https://blog.morphisec.com/fin7-not-finished-morphisec-spots-new-campaign](https://blog.morphisec.com/fin7-not-finished-morphisec-spots-new-campaign)</li></ul>  |
| **Author**               | Jason Lynch |
| Other Tags           | <ul><li>FIN7</li><li>car.2013-05-002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: MS Office Product Spawning Exe in User Dir
id: aa3a6f94-890e-4e22-b634-ffdfd54792cc
status: experimental
description: Detects an executable in the users directory started from Microsoft Word, Excel, Powerpoint, Publisher or Visio
references:
    - sha256=23160972c6ae07f740800fa28e421a81d7c0ca5d5cab95bc082b4a986fbac57c
    - https://blog.morphisec.com/fin7-not-finished-morphisec-spots-new-campaign
tags:
    - attack.execution
    - attack.defense_evasion
    - attack.t1059
    - attack.t1202
    - FIN7
    - car.2013-05-002
author: Jason Lynch 
date: 2019/04/02
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage:
            - '*\WINWORD.EXE'
            - '*\EXCEL.EXE'
            - '*\POWERPNT.exe'
            - '*\MSPUB.exe'
            - '*\VISIO.exe'
            - '*\OUTLOOK.EXE'
        Image:
            - 'C:\users\\*.exe'
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
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "ParentImage.*.*\\WINWORD.EXE" -or $_.message -match "ParentImage.*.*\\EXCEL.EXE" -or $_.message -match "ParentImage.*.*\\POWERPNT.exe" -or $_.message -match "ParentImage.*.*\\MSPUB.exe" -or $_.message -match "ParentImage.*.*\\VISIO.exe" -or $_.message -match "ParentImage.*.*\\OUTLOOK.EXE") -and ($_.message -match "Image.*C:\\users\\.*.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.ParentImage.keyword:(*\\WINWORD.EXE OR *\\EXCEL.EXE OR *\\POWERPNT.exe OR *\\MSPUB.exe OR *\\VISIO.exe OR *\\OUTLOOK.EXE) AND winlog.event_data.Image.keyword:(C\:\\users\\*.exe))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/aa3a6f94-890e-4e22-b634-ffdfd54792cc <<EOF
{
  "metadata": {
    "title": "MS Office Product Spawning Exe in User Dir",
    "description": "Detects an executable in the users directory started from Microsoft Word, Excel, Powerpoint, Publisher or Visio",
    "tags": [
      "attack.execution",
      "attack.defense_evasion",
      "attack.t1059",
      "attack.t1202",
      "FIN7",
      "car.2013-05-002"
    ],
    "query": "(winlog.event_data.ParentImage.keyword:(*\\\\WINWORD.EXE OR *\\\\EXCEL.EXE OR *\\\\POWERPNT.exe OR *\\\\MSPUB.exe OR *\\\\VISIO.exe OR *\\\\OUTLOOK.EXE) AND winlog.event_data.Image.keyword:(C\\:\\\\users\\\\*.exe))"
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
                    "query": "(winlog.event_data.ParentImage.keyword:(*\\\\WINWORD.EXE OR *\\\\EXCEL.EXE OR *\\\\POWERPNT.exe OR *\\\\MSPUB.exe OR *\\\\VISIO.exe OR *\\\\OUTLOOK.EXE) AND winlog.event_data.Image.keyword:(C\\:\\\\users\\\\*.exe))",
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
        "subject": "Sigma Rule 'MS Office Product Spawning Exe in User Dir'",
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
(ParentImage.keyword:(*\\WINWORD.EXE *\\EXCEL.EXE *\\POWERPNT.exe *\\MSPUB.exe *\\VISIO.exe *\\OUTLOOK.EXE) AND Image.keyword:(C\:\\users\\*.exe))
```


### splunk
    
```
((ParentImage="*\\WINWORD.EXE" OR ParentImage="*\\EXCEL.EXE" OR ParentImage="*\\POWERPNT.exe" OR ParentImage="*\\MSPUB.exe" OR ParentImage="*\\VISIO.exe" OR ParentImage="*\\OUTLOOK.EXE") (Image="C:\\users\\*.exe")) | table CommandLine,ParentCommandLine
```


### logpoint
    
```
(event_id="1" ParentImage IN ["*\\WINWORD.EXE", "*\\EXCEL.EXE", "*\\POWERPNT.exe", "*\\MSPUB.exe", "*\\VISIO.exe", "*\\OUTLOOK.EXE"] Image IN ["C:\\users\\*.exe"])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*\WINWORD\.EXE|.*.*\EXCEL\.EXE|.*.*\POWERPNT\.exe|.*.*\MSPUB\.exe|.*.*\VISIO\.exe|.*.*\OUTLOOK\.EXE))(?=.*(?:.*C:\users\\.*\.exe)))'
```



