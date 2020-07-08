| Title                    | Password Dumper Remote Thread in LSASS       |
|:-------------------------|:------------------|
| **Description**          | Detects password dumper activity by monitoring remote thread creation EventID 8 in combination with the lsass.exe process as TargetImage. The process in field Process is the malicious program. A single execution can lead to hundreds of events. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1003: OS Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              | <ul><li>[T1003: OS Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   | stable |
| **References**           | <ul><li>[https://jpcertcc.github.io/ToolAnalysisResultSheet/details/WCE.htm](https://jpcertcc.github.io/ToolAnalysisResultSheet/details/WCE.htm)</li></ul>  |
| **Author**               | Thomas Patzke |
| Other Tags           | <ul><li>attack.s0005</li><li>attack.t1003.001</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Password Dumper Remote Thread in LSASS
id: f239b326-2f41-4d6b-9dfa-c846a60ef505
description: Detects password dumper activity by monitoring remote thread creation EventID 8 in combination with the lsass.exe process as TargetImage. The process in field Process is the malicious program. A single execution can lead to hundreds of events.
references:
    - https://jpcertcc.github.io/ToolAnalysisResultSheet/details/WCE.htm
status: stable
author: Thomas Patzke
date: 2017/02/19
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 8
        TargetImage: 'C:\Windows\System32\lsass.exe'
        StartModule:
    condition: selection
tags:
    - attack.credential_access
    - attack.t1003
    - attack.s0005
    - attack.t1003.001
falsepositives:
    - unknown
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "8" -and $_.message -match "TargetImage.*C:\\Windows\\System32\\lsass.exe" -and -not StartModule="*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND winlog.event_id:"8" AND winlog.event_data.TargetImage:"C\:\\Windows\\System32\\lsass.exe" AND NOT _exists_:winlog.event_data.StartModule)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/f239b326-2f41-4d6b-9dfa-c846a60ef505 <<EOF
{
  "metadata": {
    "title": "Password Dumper Remote Thread in LSASS",
    "description": "Detects password dumper activity by monitoring remote thread creation EventID 8 in combination with the lsass.exe process as TargetImage. The process in field Process is the malicious program. A single execution can lead to hundreds of events.",
    "tags": [
      "attack.credential_access",
      "attack.t1003",
      "attack.s0005",
      "attack.t1003.001"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"8\" AND winlog.event_data.TargetImage:\"C\\:\\\\Windows\\\\System32\\\\lsass.exe\" AND NOT _exists_:winlog.event_data.StartModule)"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"8\" AND winlog.event_data.TargetImage:\"C\\:\\\\Windows\\\\System32\\\\lsass.exe\" AND NOT _exists_:winlog.event_data.StartModule)",
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
        "subject": "Sigma Rule 'Password Dumper Remote Thread in LSASS'",
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
(EventID:"8" AND TargetImage:"C\:\\Windows\\System32\\lsass.exe" AND NOT _exists_:StartModule)
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="8" TargetImage="C:\\Windows\\System32\\lsass.exe" NOT StartModule="*")
```


### logpoint
    
```
(event_id="8" TargetImage="C:\\Windows\\System32\\lsass.exe" -StartModule=*)
```


### grep
    
```
grep -P '^(?:.*(?=.*8)(?=.*C:\Windows\System32\lsass\.exe)(?=.*(?!StartModule)))'
```



