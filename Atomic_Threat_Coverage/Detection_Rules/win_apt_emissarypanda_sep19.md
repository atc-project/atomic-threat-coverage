| Title                    | Emissary Panda Malware SLLauncher       |
|:-------------------------|:------------------|
| **Description**          | Detects the execution of DLL side-loading malware used by threat group Emissary Panda aka APT27 |
| **ATT&amp;CK Tactic**    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| **ATT&amp;CK Technique** |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| **Data Needed**          | <ul><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://app.any.run/tasks/579e7587-f09d-4aae-8b07-472833262965](https://app.any.run/tasks/579e7587-f09d-4aae-8b07-472833262965)</li><li>[https://twitter.com/cyb3rops/status/1168863899531132929](https://twitter.com/cyb3rops/status/1168863899531132929)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Emissary Panda Malware SLLauncher
id: 9aa01d62-7667-4d3b-acb8-8cb5103e2014
status: experimental
description: Detects the execution of DLL side-loading malware used by threat group Emissary Panda aka APT27
references:
    - https://app.any.run/tasks/579e7587-f09d-4aae-8b07-472833262965
    - https://twitter.com/cyb3rops/status/1168863899531132929
author: Florian Roth
date: 2018/09/03
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage: '*\sllauncher.exe'
        Image: '*\svchost.exe'
    condition: selection
falsepositives:
    - Unknown
level: critical

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "ParentImage.*.*\\sllauncher.exe" -and $_.message -match "Image.*.*\\svchost.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.ParentImage.keyword:*\\sllauncher.exe AND winlog.event_data.Image.keyword:*\\svchost.exe)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/9aa01d62-7667-4d3b-acb8-8cb5103e2014 <<EOF
{
  "metadata": {
    "title": "Emissary Panda Malware SLLauncher",
    "description": "Detects the execution of DLL side-loading malware used by threat group Emissary Panda aka APT27",
    "tags": "",
    "query": "(winlog.event_data.ParentImage.keyword:*\\\\sllauncher.exe AND winlog.event_data.Image.keyword:*\\\\svchost.exe)"
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
                    "query": "(winlog.event_data.ParentImage.keyword:*\\\\sllauncher.exe AND winlog.event_data.Image.keyword:*\\\\svchost.exe)",
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
        "subject": "Sigma Rule 'Emissary Panda Malware SLLauncher'",
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
(ParentImage.keyword:*\\sllauncher.exe AND Image.keyword:*\\svchost.exe)
```


### splunk
    
```
(ParentImage="*\\sllauncher.exe" Image="*\\svchost.exe")
```


### logpoint
    
```
(event_id="1" ParentImage="*\\sllauncher.exe" Image="*\\svchost.exe")
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\sllauncher\.exe)(?=.*.*\svchost\.exe))'
```



