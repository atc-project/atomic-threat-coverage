| Title                    | Windows Defender Threat Detection Disabled       |
|:-------------------------|:------------------|
| **Description**          | Detects disabling Windows Defender threat protection |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1089: Disabling Security Tools](https://attack.mitre.org/techniques/T1089)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Administrator actions</li></ul>  |
| **Development Status**   | stable |
| **References**           | <ul><li>[https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-antivirus/troubleshoot-windows-defender-antivirus](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-antivirus/troubleshoot-windows-defender-antivirus)</li></ul>  |
| **Author**               | Ján Trenčanský |
| Other Tags           | <ul><li>attack.t1562.001</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Windows Defender Threat Detection Disabled
id: fe34868f-6e0e-4882-81f6-c43aa8f15b62
description: Detects disabling Windows Defender threat protection
date: 2020/07/28
author: Ján Trenčanský
references:
    - https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-antivirus/troubleshoot-windows-defender-antivirus
status: stable
tags:
    - attack.defense_evasion
    - attack.t1089
    - attack.t1562.001
logsource:
    product: windows
    service: windefend
detection:
    selection:
        EventID:
            - 5001
            - 5010
            - 5012
            - 5101
    condition: selection
falsepositives:
    - Administrator actions
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Windows Defender/Operational | where {(($_.ID -eq "5001" -or $_.ID -eq "5010" -or $_.ID -eq "5012" -or $_.ID -eq "5101")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-Windows\ Defender\/Operational" AND winlog.event_id:("5001" OR "5010" OR "5012" OR "5101"))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/fe34868f-6e0e-4882-81f6-c43aa8f15b62 <<EOF
{
  "metadata": {
    "title": "Windows Defender Threat Detection Disabled",
    "description": "Detects disabling Windows Defender threat protection",
    "tags": [
      "attack.defense_evasion",
      "attack.t1089",
      "attack.t1562.001"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Windows\\ Defender\\/Operational\" AND winlog.event_id:(\"5001\" OR \"5010\" OR \"5012\" OR \"5101\"))"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Windows\\ Defender\\/Operational\" AND winlog.event_id:(\"5001\" OR \"5010\" OR \"5012\" OR \"5101\"))",
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
        "subject": "Sigma Rule 'Windows Defender Threat Detection Disabled'",
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
EventID:("5001" "5010" "5012" "5101")
```


### splunk
    
```
(EventCode="5001" OR EventCode="5010" OR EventCode="5012" OR EventCode="5101")
```


### logpoint
    
```
event_id IN ["5001", "5010", "5012", "5101"]
```


### grep
    
```
grep -P '^(?:.*5001|.*5010|.*5012|.*5101)'
```



