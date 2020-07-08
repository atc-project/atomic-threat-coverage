| Title                    | Suspicious GUP Usage       |
|:-------------------------|:------------------|
| **Description**          | Detects execution of the Notepad++ updater in a suspicious directory, which is often used in DLL side-loading attacks |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1073: DLL Side-Loading](https://attack.mitre.org/techniques/T1073)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0001_4688_windows_process_creation](../Data_Needed/DN0001_4688_windows_process_creation.md)</li><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Execution of tools named GUP.exe and located in folders different than Notepad++\updater</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.fireeye.com/blog/threat-research/2018/09/apt10-targeting-japanese-corporations-using-updated-ttps.html](https://www.fireeye.com/blog/threat-research/2018/09/apt10-targeting-japanese-corporations-using-updated-ttps.html)</li></ul>  |
| **Author**               | Florian Roth |
| Other Tags           | <ul><li>attack.t1574.002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Suspicious GUP Usage
id: 0a4f6091-223b-41f6-8743-f322ec84930b
description: Detects execution of the Notepad++ updater in a suspicious directory, which is often used in DLL side-loading attacks
status: experimental
references:
    - https://www.fireeye.com/blog/threat-research/2018/09/apt10-targeting-japanese-corporations-using-updated-ttps.html
tags:
    - attack.defense_evasion
    - attack.t1073
    - attack.t1574.002
author: Florian Roth
date: 2019/02/06
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: '*\GUP.exe'
    filter:
        Image:
            - 'C:\Users\\*\AppData\Local\Notepad++\updater\gup.exe'
            - 'C:\Users\\*\AppData\Roaming\Notepad++\updater\gup.exe'
            - 'C:\Program Files\Notepad++\updater\gup.exe'
            - 'C:\Program Files (x86)\Notepad++\updater\gup.exe'
    condition: selection and not filter
falsepositives:
    - Execution of tools named GUP.exe and located in folders different than Notepad++\updater
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\\GUP.exe" -and  -not (($_.message -match "Image.*C:\\Users\\.*\\AppData\\Local\\Notepad\+\+\\updater\\gup.exe" -or $_.message -match "Image.*C:\\Users\\.*\\AppData\\Roaming\\Notepad\+\+\\updater\\gup.exe" -or $_.message -match "C:\\Program Files\\Notepad\+\+\\updater\\gup.exe" -or $_.message -match "C:\\Program Files (x86)\\Notepad\+\+\\updater\\gup.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:*\\GUP.exe AND (NOT (winlog.event_data.Image.keyword:(C\:\\Users\\*\\AppData\\Local\\Notepad\+\+\\updater\\gup.exe OR C\:\\Users\\*\\AppData\\Roaming\\Notepad\+\+\\updater\\gup.exe OR C\:\\Program\ Files\\Notepad\+\+\\updater\\gup.exe OR C\:\\Program\ Files\ \(x86\)\\Notepad\+\+\\updater\\gup.exe))))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/0a4f6091-223b-41f6-8743-f322ec84930b <<EOF
{
  "metadata": {
    "title": "Suspicious GUP Usage",
    "description": "Detects execution of the Notepad++ updater in a suspicious directory, which is often used in DLL side-loading attacks",
    "tags": [
      "attack.defense_evasion",
      "attack.t1073",
      "attack.t1574.002"
    ],
    "query": "(winlog.event_data.Image.keyword:*\\\\GUP.exe AND (NOT (winlog.event_data.Image.keyword:(C\\:\\\\Users\\\\*\\\\AppData\\\\Local\\\\Notepad\\+\\+\\\\updater\\\\gup.exe OR C\\:\\\\Users\\\\*\\\\AppData\\\\Roaming\\\\Notepad\\+\\+\\\\updater\\\\gup.exe OR C\\:\\\\Program\\ Files\\\\Notepad\\+\\+\\\\updater\\\\gup.exe OR C\\:\\\\Program\\ Files\\ \\(x86\\)\\\\Notepad\\+\\+\\\\updater\\\\gup.exe))))"
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
                    "query": "(winlog.event_data.Image.keyword:*\\\\GUP.exe AND (NOT (winlog.event_data.Image.keyword:(C\\:\\\\Users\\\\*\\\\AppData\\\\Local\\\\Notepad\\+\\+\\\\updater\\\\gup.exe OR C\\:\\\\Users\\\\*\\\\AppData\\\\Roaming\\\\Notepad\\+\\+\\\\updater\\\\gup.exe OR C\\:\\\\Program\\ Files\\\\Notepad\\+\\+\\\\updater\\\\gup.exe OR C\\:\\\\Program\\ Files\\ \\(x86\\)\\\\Notepad\\+\\+\\\\updater\\\\gup.exe))))",
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
        "subject": "Sigma Rule 'Suspicious GUP Usage'",
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
(Image.keyword:*\\GUP.exe AND (NOT (Image.keyword:(C\:\\Users\\*\\AppData\\Local\\Notepad\+\+\\updater\\gup.exe C\:\\Users\\*\\AppData\\Roaming\\Notepad\+\+\\updater\\gup.exe C\:\\Program Files\\Notepad\+\+\\updater\\gup.exe C\:\\Program Files \(x86\)\\Notepad\+\+\\updater\\gup.exe))))
```


### splunk
    
```
(Image="*\\GUP.exe" NOT ((Image="C:\\Users\\*\\AppData\\Local\\Notepad++\\updater\\gup.exe" OR Image="C:\\Users\\*\\AppData\\Roaming\\Notepad++\\updater\\gup.exe" OR Image="C:\\Program Files\\Notepad++\\updater\\gup.exe" OR Image="C:\\Program Files (x86)\\Notepad++\\updater\\gup.exe")))
```


### logpoint
    
```
(event_id="1" Image="*\\GUP.exe"  -(Image IN ["C:\\Users\\*\\AppData\\Local\\Notepad++\\updater\\gup.exe", "C:\\Users\\*\\AppData\\Roaming\\Notepad++\\updater\\gup.exe", "C:\\Program Files\\Notepad++\\updater\\gup.exe", "C:\\Program Files (x86)\\Notepad++\\updater\\gup.exe"]))
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\GUP\.exe)(?=.*(?!.*(?:.*(?=.*(?:.*C:\Users\\.*\AppData\Local\Notepad\+\+\updater\gup\.exe|.*C:\Users\\.*\AppData\Roaming\Notepad\+\+\updater\gup\.exe|.*C:\Program Files\Notepad\+\+\updater\gup\.exe|.*C:\Program Files \(x86\)\Notepad\+\+\updater\gup\.exe))))))'
```



