| Title                    | Findstr Launching .lnk File       |
|:-------------------------|:------------------|
| **Description**          | Detects usage of findstr to identify and execute a lnk file as seen within the HHS redirect attack |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1202: Indirect Command Execution](https://attack.mitre.org/techniques/T1202)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1202: Indirect Command Execution](../Triggers/T1202.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.bleepingcomputer.com/news/security/hhsgov-open-redirect-used-by-coronavirus-phishing-to-spread-malware/](https://www.bleepingcomputer.com/news/security/hhsgov-open-redirect-used-by-coronavirus-phishing-to-spread-malware/)</li></ul>  |
| **Author**               | Trent Liffick |


## Detection Rules

### Sigma rule

```
title: Findstr Launching .lnk File
id: 33339be3-148b-4e16-af56-ad16ec6c7e7b
description: Detects usage of findstr to identify and execute a lnk file as seen within the HHS redirect attack
status: experimental
references:
    - https://www.bleepingcomputer.com/news/security/hhsgov-open-redirect-used-by-coronavirus-phishing-to-spread-malware/
tags:
    - attack.defense_evasion
    - attack.t1202
author: Trent Liffick
date: 2020/05/01
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: '*\findstr.exe'
        CommandLine: '*.lnk'
    condition: selection
fields:
    - Image
    - CommandLine
    - ParentCommandLine
falsepositives:
    - unknown
level: medium

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\\findstr.exe" -and $_.message -match "CommandLine.*.*.lnk") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:*\\findstr.exe AND winlog.event_data.CommandLine.keyword:*.lnk)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/33339be3-148b-4e16-af56-ad16ec6c7e7b <<EOF
{
  "metadata": {
    "title": "Findstr Launching .lnk File",
    "description": "Detects usage of findstr to identify and execute a lnk file as seen within the HHS redirect attack",
    "tags": [
      "attack.defense_evasion",
      "attack.t1202"
    ],
    "query": "(winlog.event_data.Image.keyword:*\\\\findstr.exe AND winlog.event_data.CommandLine.keyword:*.lnk)"
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
                    "query": "(winlog.event_data.Image.keyword:*\\\\findstr.exe AND winlog.event_data.CommandLine.keyword:*.lnk)",
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
        "subject": "Sigma Rule 'Findstr Launching .lnk File'",
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
(Image.keyword:*\\findstr.exe AND CommandLine.keyword:*.lnk)
```


### splunk
    
```
(Image="*\\findstr.exe" CommandLine="*.lnk") | table Image,CommandLine,ParentCommandLine
```


### logpoint
    
```
(event_id="1" Image="*\\findstr.exe" CommandLine="*.lnk")
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\findstr\.exe)(?=.*.*\.lnk))'
```



