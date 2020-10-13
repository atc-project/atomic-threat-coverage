| Title                    | PowerShell Rundll32 Remote Thread Creation       |
|:-------------------------|:------------------|
| **Description**          | Detects PowerShell remote thread creation in Rundll32.exe |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1085: Rundll32](https://attack.mitre.org/techniques/T1085)</li><li>[T1218.011: Rundll32](https://attack.mitre.org/techniques/T1218/011)</li><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li><li>[T1059.001: PowerShell](https://attack.mitre.org/techniques/T1059/001)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0012_8_windows_sysmon_CreateRemoteThread](../Data_Needed/DN_0012_8_windows_sysmon_CreateRemoteThread.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1218.011: Rundll32](../Triggers/T1218.011.md)</li><li>[T1059.001: PowerShell](../Triggers/T1059.001.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unkown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.fireeye.com/blog/threat-research/2018/06/bring-your-own-land-novel-red-teaming-technique.html](https://www.fireeye.com/blog/threat-research/2018/06/bring-your-own-land-novel-red-teaming-technique.html)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: PowerShell Rundll32 Remote Thread Creation
id: 99b97608-3e21-4bfe-8217-2a127c396a0e
status: experimental
description: Detects PowerShell remote thread creation in Rundll32.exe
author: Florian Roth
references:
    - https://www.fireeye.com/blog/threat-research/2018/06/bring-your-own-land-novel-red-teaming-technique.html
date: 2018/06/25
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 8
        SourceImage: '*\powershell.exe'
        TargetImage: '*\rundll32.exe'
    condition: selection
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1085          # an old one
    - attack.t1218.011
    - attack.t1086          # an old one
    - attack.t1059.001
falsepositives:
    - Unkown
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "8" -and $_.message -match "SourceImage.*.*\\powershell.exe" -and $_.message -match "TargetImage.*.*\\rundll32.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND winlog.event_id:"8" AND winlog.event_data.SourceImage.keyword:*\\powershell.exe AND winlog.event_data.TargetImage.keyword:*\\rundll32.exe)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/99b97608-3e21-4bfe-8217-2a127c396a0e <<EOF
{
  "metadata": {
    "title": "PowerShell Rundll32 Remote Thread Creation",
    "description": "Detects PowerShell remote thread creation in Rundll32.exe",
    "tags": [
      "attack.defense_evasion",
      "attack.execution",
      "attack.t1085",
      "attack.t1218.011",
      "attack.t1086",
      "attack.t1059.001"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"8\" AND winlog.event_data.SourceImage.keyword:*\\\\powershell.exe AND winlog.event_data.TargetImage.keyword:*\\\\rundll32.exe)"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"8\" AND winlog.event_data.SourceImage.keyword:*\\\\powershell.exe AND winlog.event_data.TargetImage.keyword:*\\\\rundll32.exe)",
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
        "subject": "Sigma Rule 'PowerShell Rundll32 Remote Thread Creation'",
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
(EventID:"8" AND SourceImage.keyword:*\\powershell.exe AND TargetImage.keyword:*\\rundll32.exe)
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="8" SourceImage="*\\powershell.exe" TargetImage="*\\rundll32.exe")
```


### logpoint
    
```
(event_id="8" SourceImage="*\\powershell.exe" TargetImage="*\\rundll32.exe")
```


### grep
    
```
grep -P '^(?:.*(?=.*8)(?=.*.*\powershell\.exe)(?=.*.*\rundll32\.exe))'
```



