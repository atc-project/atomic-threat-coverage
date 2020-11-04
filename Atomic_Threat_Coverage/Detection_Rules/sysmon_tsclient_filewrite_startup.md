| Title                    | Hijack Legit RDP Session to Move Laterally       |
|:-------------------------|:------------------|
| **Description**          | Detects the usage of tsclient share to place a backdoor on the RDP source machine's startup folder |
| **ATT&amp;CK Tactic**    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| **ATT&amp;CK Technique** |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| **Data Needed**          | <ul><li>[DN_0015_11_windows_sysmon_FileCreate](../Data_Needed/DN_0015_11_windows_sysmon_FileCreate.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Samir Bousseaden |


## Detection Rules

### Sigma rule

```
title: Hijack Legit RDP Session to Move Laterally
id: 52753ea4-b3a0-4365-910d-36cff487b789
status: experimental
description: Detects the usage of tsclient share to place a backdoor on the RDP source machine's startup folder
date: 2019/02/21
author: Samir Bousseaden
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 11
        Image: '*\mstsc.exe'
        TargetFileName: '*\Microsoft\Windows\Start Menu\Programs\Startup\\*'
    condition: selection
falsepositives:
    - unknown
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "11" -and $_.message -match "Image.*.*\\mstsc.exe" -and $_.message -match "TargetFileName.*.*\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND winlog.event_id:"11" AND winlog.event_data.Image.keyword:*\\mstsc.exe AND TargetFileName.keyword:*\\Microsoft\\Windows\\Start\ Menu\\Programs\\Startup\\*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/52753ea4-b3a0-4365-910d-36cff487b789 <<EOF
{
  "metadata": {
    "title": "Hijack Legit RDP Session to Move Laterally",
    "description": "Detects the usage of tsclient share to place a backdoor on the RDP source machine's startup folder",
    "tags": "",
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"11\" AND winlog.event_data.Image.keyword:*\\\\mstsc.exe AND TargetFileName.keyword:*\\\\Microsoft\\\\Windows\\\\Start\\ Menu\\\\Programs\\\\Startup\\\\*)"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"11\" AND winlog.event_data.Image.keyword:*\\\\mstsc.exe AND TargetFileName.keyword:*\\\\Microsoft\\\\Windows\\\\Start\\ Menu\\\\Programs\\\\Startup\\\\*)",
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
        "subject": "Sigma Rule 'Hijack Legit RDP Session to Move Laterally'",
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
(EventID:"11" AND Image.keyword:*\\mstsc.exe AND TargetFileName.keyword:*\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*)
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="11" Image="*\\mstsc.exe" TargetFileName="*\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*")
```


### logpoint
    
```
(event_id="11" Image="*\\mstsc.exe" TargetFileName="*\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*")
```


### grep
    
```
grep -P '^(?:.*(?=.*11)(?=.*.*\mstsc\.exe)(?=.*.*\Microsoft\Windows\Start Menu\Programs\Startup\\.*))'
```



