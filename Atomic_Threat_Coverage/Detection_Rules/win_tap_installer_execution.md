| Title                    | Tap Installer Execution       |
|:-------------------------|:------------------|
| **Description**          | Well-known TAP software installation. Possible preparation for data exfiltration using tunneling techniques |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0010: Exfiltration](https://attack.mitre.org/tactics/TA0010)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1048: Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0001_4688_windows_process_creation](../Data_Needed/DN0001_4688_windows_process_creation.md)</li><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1048: Exfiltration Over Alternative Protocol](../Triggers/T1048.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Legitimate OpenVPN TAP insntallation</li></ul>  |
| **Development Status**   | experimental |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Daniil Yugoslavskiy, Ian Davis, oscd.community |


## Detection Rules

### Sigma rule

```
title: Tap Installer Execution
id: 99793437-3e16-439b-be0f-078782cf953d
description: Well-known TAP software installation. Possible preparation for data exfiltration using tunneling techniques
status: experimental
author: Daniil Yugoslavskiy, Ian Davis, oscd.community
date: 2019/10/24
tags:
    - attack.exfiltration
    - attack.t1048
logsource:
     category: process_creation
     product: windows
detection:
    selection:
        Image|endswith: '\tapinstall.exe'
    condition: selection
falsepositives:
    - Legitimate OpenVPN TAP insntallation
level: medium

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\\tapinstall.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.Image.keyword:*\\tapinstall.exe
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/99793437-3e16-439b-be0f-078782cf953d <<EOF
{
  "metadata": {
    "title": "Tap Installer Execution",
    "description": "Well-known TAP software installation. Possible preparation for data exfiltration using tunneling techniques",
    "tags": [
      "attack.exfiltration",
      "attack.t1048"
    ],
    "query": "winlog.event_data.Image.keyword:*\\\\tapinstall.exe"
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
                    "query": "winlog.event_data.Image.keyword:*\\\\tapinstall.exe",
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
        "subject": "Sigma Rule 'Tap Installer Execution'",
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
Image.keyword:*\\tapinstall.exe
```


### splunk
    
```
Image="*\\tapinstall.exe"
```


### logpoint
    
```
(event_id="1" Image="*\\tapinstall.exe")
```


### grep
    
```
grep -P '^.*\tapinstall\.exe'
```



