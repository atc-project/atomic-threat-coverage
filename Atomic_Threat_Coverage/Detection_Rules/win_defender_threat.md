| Title                    | Windows Defender Threat Detected       |
|:-------------------------|:------------------|
| **Description**          | Detects all actions taken by Windows Defender malware detection engines |
| **ATT&amp;CK Tactic**    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| **ATT&amp;CK Technique** |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>unlikely</li></ul>  |
| **Development Status**   | stable |
| **References**           | <ul><li>[https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-antivirus/troubleshoot-windows-defender-antivirus](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-antivirus/troubleshoot-windows-defender-antivirus)</li></ul>  |
| **Author**               | Ján Trenčanský |


## Detection Rules

### Sigma rule

```
title: Windows Defender Threat Detected
id: 57b649ef-ff42-4fb0-8bf6-62da243a1708
description: Detects all actions taken by Windows Defender malware detection engines
date: 2020/07/28
author: Ján Trenčanský
references:
    - https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-antivirus/troubleshoot-windows-defender-antivirus
status: stable
logsource:
    product: windows
    service: windefend
detection:
    selection:
        EventID:
            - 1006
            - 1116
            - 1015
            - 1117
    condition: selection
falsepositives:
    - unlikely
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Windows Defender/Operational | where {(($_.ID -eq "1006" -or $_.ID -eq "1116" -or $_.ID -eq "1015" -or $_.ID -eq "1117")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-Windows\ Defender\/Operational" AND winlog.event_id:("1006" OR "1116" OR "1015" OR "1117"))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/57b649ef-ff42-4fb0-8bf6-62da243a1708 <<EOF
{
  "metadata": {
    "title": "Windows Defender Threat Detected",
    "description": "Detects all actions taken by Windows Defender malware detection engines",
    "tags": "",
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Windows\\ Defender\\/Operational\" AND winlog.event_id:(\"1006\" OR \"1116\" OR \"1015\" OR \"1117\"))"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Windows\\ Defender\\/Operational\" AND winlog.event_id:(\"1006\" OR \"1116\" OR \"1015\" OR \"1117\"))",
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
        "subject": "Sigma Rule 'Windows Defender Threat Detected'",
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
EventID:("1006" "1116" "1015" "1117")
```


### splunk
    
```
(EventCode="1006" OR EventCode="1116" OR EventCode="1015" OR EventCode="1117")
```


### logpoint
    
```
event_id IN ["1006", "1116", "1015", "1117"]
```


### grep
    
```
grep -P '^(?:.*1006|.*1116|.*1015|.*1117)'
```



