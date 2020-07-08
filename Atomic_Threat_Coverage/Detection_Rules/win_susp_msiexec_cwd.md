| Title                    | Suspicious MsiExec Directory       |
|:-------------------------|:------------------|
| **Description**          | Detects suspicious msiexec process starts in an uncommon directory |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1036: Masquerading](https://attack.mitre.org/techniques/T1036)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0001_4688_windows_process_creation](../Data_Needed/DN0001_4688_windows_process_creation.md)</li><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://twitter.com/200_okay_/status/1194765831911215104](https://twitter.com/200_okay_/status/1194765831911215104)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Suspicious MsiExec Directory
id: e22a6eb2-f8a5-44b5-8b44-a2dbd47b1144
status: experimental
description: Detects suspicious msiexec process starts in an uncommon directory
references:
    - https://twitter.com/200_okay_/status/1194765831911215104
tags:
    - attack.defense_evasion
    - attack.t1036
author: Florian Roth
date: 2019/11/14
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: '*\msiexec.exe'
    filter:
        Image: 
            - 'C:\Windows\System32\\*'
            - 'C:\Windows\SysWOW64\\*'
            - 'C:\Windows\WinSxS\\*' 
    condition: selection and not filter
falsepositives:
    - Unknown
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\\msiexec.exe" -and  -not (($_.message -match "Image.*C:\\Windows\\System32\\.*" -or $_.message -match "Image.*C:\\Windows\\SysWOW64\\.*" -or $_.message -match "Image.*C:\\Windows\\WinSxS\\.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:*\\msiexec.exe AND (NOT (winlog.event_data.Image.keyword:(C\:\\Windows\\System32\\* OR C\:\\Windows\\SysWOW64\\* OR C\:\\Windows\\WinSxS\\*))))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/e22a6eb2-f8a5-44b5-8b44-a2dbd47b1144 <<EOF
{
  "metadata": {
    "title": "Suspicious MsiExec Directory",
    "description": "Detects suspicious msiexec process starts in an uncommon directory",
    "tags": [
      "attack.defense_evasion",
      "attack.t1036"
    ],
    "query": "(winlog.event_data.Image.keyword:*\\\\msiexec.exe AND (NOT (winlog.event_data.Image.keyword:(C\\:\\\\Windows\\\\System32\\\\* OR C\\:\\\\Windows\\\\SysWOW64\\\\* OR C\\:\\\\Windows\\\\WinSxS\\\\*))))"
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
                    "query": "(winlog.event_data.Image.keyword:*\\\\msiexec.exe AND (NOT (winlog.event_data.Image.keyword:(C\\:\\\\Windows\\\\System32\\\\* OR C\\:\\\\Windows\\\\SysWOW64\\\\* OR C\\:\\\\Windows\\\\WinSxS\\\\*))))",
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
        "subject": "Sigma Rule 'Suspicious MsiExec Directory'",
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
(Image.keyword:*\\msiexec.exe AND (NOT (Image.keyword:(C\:\\Windows\\System32\\* C\:\\Windows\\SysWOW64\\* C\:\\Windows\\WinSxS\\*))))
```


### splunk
    
```
(Image="*\\msiexec.exe" NOT ((Image="C:\\Windows\\System32\\*" OR Image="C:\\Windows\\SysWOW64\\*" OR Image="C:\\Windows\\WinSxS\\*")))
```


### logpoint
    
```
(event_id="1" Image="*\\msiexec.exe"  -(Image IN ["C:\\Windows\\System32\\*", "C:\\Windows\\SysWOW64\\*", "C:\\Windows\\WinSxS\\*"]))
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\msiexec\.exe)(?=.*(?!.*(?:.*(?=.*(?:.*C:\Windows\System32\\.*|.*C:\Windows\SysWOW64\\.*|.*C:\Windows\WinSxS\\.*))))))'
```



