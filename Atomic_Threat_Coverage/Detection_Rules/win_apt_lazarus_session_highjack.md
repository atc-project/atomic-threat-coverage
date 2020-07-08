| Title                    | Lazarus Session Highjacker       |
|:-------------------------|:------------------|
| **Description**          | Detects executables launched outside their default directories as used by Lazarus Group (Bluenoroff) |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1036: Masquerading](https://attack.mitre.org/techniques/T1036)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0001_4688_windows_process_creation](../Data_Needed/DN0001_4688_windows_process_creation.md)</li><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/07180244/Lazarus_Under_The_Hood_PDF_final.pdf](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/07180244/Lazarus_Under_The_Hood_PDF_final.pdf)</li></ul>  |
| **Author**               | Trent Liffick (@tliffick) |
| Other Tags           | <ul><li>attack.t1036.005</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Lazarus Session Highjacker
id: 3f7f5b0b-5b16-476c-a85f-ab477f6dd24b
description: Detects executables launched outside their default directories as used by Lazarus Group (Bluenoroff)
status: experimental
references:
    - https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/07180244/Lazarus_Under_The_Hood_PDF_final.pdf
tags:
    - attack.defense_evasion
    - attack.t1036
    - attack.t1036.005
author: Trent Liffick (@tliffick)
date: 2020/06/03
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: 
            - '*\mstdc.exe'
            - '*\gpvc.exe'
    filter:
        Image:
            - 'C:\Windows\System32\\*'
            - 'C:\Windows\SysWOW64\\*'
    condition: selection and not filter
falsepositives:
    - unknown
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "Image.*.*\\mstdc.exe" -or $_.message -match "Image.*.*\\gpvc.exe") -and  -not (($_.message -match "Image.*C:\\Windows\\System32\\.*" -or $_.message -match "Image.*C:\\Windows\\SysWOW64\\.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:(*\\mstdc.exe OR *\\gpvc.exe) AND (NOT (winlog.event_data.Image.keyword:(C\:\\Windows\\System32\\* OR C\:\\Windows\\SysWOW64\\*))))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/3f7f5b0b-5b16-476c-a85f-ab477f6dd24b <<EOF
{
  "metadata": {
    "title": "Lazarus Session Highjacker",
    "description": "Detects executables launched outside their default directories as used by Lazarus Group (Bluenoroff)",
    "tags": [
      "attack.defense_evasion",
      "attack.t1036",
      "attack.t1036.005"
    ],
    "query": "(winlog.event_data.Image.keyword:(*\\\\mstdc.exe OR *\\\\gpvc.exe) AND (NOT (winlog.event_data.Image.keyword:(C\\:\\\\Windows\\\\System32\\\\* OR C\\:\\\\Windows\\\\SysWOW64\\\\*))))"
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
                    "query": "(winlog.event_data.Image.keyword:(*\\\\mstdc.exe OR *\\\\gpvc.exe) AND (NOT (winlog.event_data.Image.keyword:(C\\:\\\\Windows\\\\System32\\\\* OR C\\:\\\\Windows\\\\SysWOW64\\\\*))))",
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
        "subject": "Sigma Rule 'Lazarus Session Highjacker'",
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
(Image.keyword:(*\\mstdc.exe *\\gpvc.exe) AND (NOT (Image.keyword:(C\:\\Windows\\System32\\* C\:\\Windows\\SysWOW64\\*))))
```


### splunk
    
```
((Image="*\\mstdc.exe" OR Image="*\\gpvc.exe") NOT ((Image="C:\\Windows\\System32\\*" OR Image="C:\\Windows\\SysWOW64\\*")))
```


### logpoint
    
```
(event_id="1" Image IN ["*\\mstdc.exe", "*\\gpvc.exe"]  -(Image IN ["C:\\Windows\\System32\\*", "C:\\Windows\\SysWOW64\\*"]))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*\mstdc\.exe|.*.*\gpvc\.exe))(?=.*(?!.*(?:.*(?=.*(?:.*C:\Windows\System32\\.*|.*C:\Windows\SysWOW64\\.*))))))'
```



