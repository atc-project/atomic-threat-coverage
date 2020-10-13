| Title                    | Windows Defender Threat Detection Disabled       |
|:-------------------------|:------------------|
| **Description**          | Detects disabling Windows Defender threat protection |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1089: Disabling Security Tools](https://attack.mitre.org/techniques/T1089)</li><li>[T1562.001: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              | <ul><li>[T1562.001: Disable or Modify Tools](../Triggers/T1562.001.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Administrator actions</li></ul>  |
| **Development Status**   | stable |
| **References**           | <ul><li>[https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-antivirus/troubleshoot-windows-defender-antivirus](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-antivirus/troubleshoot-windows-defender-antivirus)</li></ul>  |
| **Author**               | Ján Trenčanský |


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
    - attack.t1089           # an old one
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
    selection2:
        TargetObject:
            - HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinDefend
            - HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender
            - HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender
        Details: 'DWORD (0x00000001)'
    condition: 1 of them
falsepositives:
    - Administrator actions
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Windows Defender/Operational | where {((($_.ID -eq "5001" -or $_.ID -eq "5010" -or $_.ID -eq "5012" -or $_.ID -eq "5101") -or (($_.message -match "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\WinDefend" -or $_.message -match "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender" -or $_.message -match "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender") -and $_.message -match "Details.*DWORD (0x00000001)"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-Windows\ Defender\/Operational" AND (winlog.event_id:("5001" OR "5010" OR "5012" OR "5101") OR (winlog.event_data.TargetObject:("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\WinDefend" OR "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\ Defender" OR "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\ Defender") AND winlog.event_data.Details:"DWORD\ \(0x00000001\)")))
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
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Windows\\ Defender\\/Operational\" AND (winlog.event_id:(\"5001\" OR \"5010\" OR \"5012\" OR \"5101\") OR (winlog.event_data.TargetObject:(\"HKEY_LOCAL_MACHINE\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\WinDefend\" OR \"HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\Microsoft\\\\Windows\\ Defender\" OR \"HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\Policies\\\\Microsoft\\\\Windows\\ Defender\") AND winlog.event_data.Details:\"DWORD\\ \\(0x00000001\\)\")))"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Windows\\ Defender\\/Operational\" AND (winlog.event_id:(\"5001\" OR \"5010\" OR \"5012\" OR \"5101\") OR (winlog.event_data.TargetObject:(\"HKEY_LOCAL_MACHINE\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\WinDefend\" OR \"HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\Microsoft\\\\Windows\\ Defender\" OR \"HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\Policies\\\\Microsoft\\\\Windows\\ Defender\") AND winlog.event_data.Details:\"DWORD\\ \\(0x00000001\\)\")))",
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
(EventID:("5001" "5010" "5012" "5101") OR (TargetObject:("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\WinDefend" "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender" "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender") AND Details:"DWORD \(0x00000001\)"))
```


### splunk
    
```
((EventCode="5001" OR EventCode="5010" OR EventCode="5012" OR EventCode="5101") OR ((TargetObject="HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\WinDefend" OR TargetObject="HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender" OR TargetObject="HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender") Details="DWORD (0x00000001)"))
```


### logpoint
    
```
(event_id IN ["5001", "5010", "5012", "5101"] OR (TargetObject IN ["HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\WinDefend", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender"] Details="DWORD (0x00000001)"))
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*5001|.*5010|.*5012|.*5101)|.*(?:.*(?=.*(?:.*HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinDefend|.*HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender|.*HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender))(?=.*DWORD \(0x00000001\)))))'
```



