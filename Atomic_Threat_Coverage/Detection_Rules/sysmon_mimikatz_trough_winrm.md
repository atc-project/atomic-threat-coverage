| Title                    | Mimikatz through Windows Remote Management       |
|:-------------------------|:------------------|
| **Description**          | Detects usage of mimikatz through WinRM protocol by monitoring access to lsass process by wsmprovhost.exe. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1003: OS Credential Dumping](https://attack.mitre.org/techniques/T1003)</li><li>[T1028: Windows Remote Management](https://attack.mitre.org/techniques/T1028)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0014_10_windows_sysmon_ProcessAccess](../Data_Needed/DN_0014_10_windows_sysmon_ProcessAccess.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1003: OS Credential Dumping](../Triggers/T1003.md)</li><li>[T1028: Windows Remote Management](../Triggers/T1028.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>low</li></ul>  |
| **Development Status**   | stable |
| **References**           | <ul><li>[https://pentestlab.blog/2018/05/15/lateral-movement-winrm/](https://pentestlab.blog/2018/05/15/lateral-movement-winrm/)</li></ul>  |
| **Author**               | Patryk Prauze - ING Tech |
| Other Tags           | <ul><li>attack.s0005</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Mimikatz through Windows Remote Management
id: aa35a627-33fb-4d04-a165-d33b4afca3e8
description: Detects usage of mimikatz through WinRM protocol by monitoring access to lsass process by wsmprovhost.exe.
references:
    - https://pentestlab.blog/2018/05/15/lateral-movement-winrm/
status: stable
author: Patryk Prauze - ING Tech
date: 2019/05/20
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 10
        TargetImage: 'C:\windows\system32\lsass.exe'
        SourceImage: 'C:\Windows\system32\wsmprovhost.exe'
    condition: selection
tags:
    - attack.credential_access
    - attack.execution
    - attack.t1003
    - attack.t1028
    - attack.s0005
falsepositives:
    - low
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "10" -and $_.message -match "TargetImage.*C:\\windows\\system32\\lsass.exe" -and $_.message -match "SourceImage.*C:\\Windows\\system32\\wsmprovhost.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND winlog.event_id:"10" AND winlog.event_data.TargetImage:"C\:\\windows\\system32\\lsass.exe" AND winlog.event_data.SourceImage:"C\:\\Windows\\system32\\wsmprovhost.exe")
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/aa35a627-33fb-4d04-a165-d33b4afca3e8 <<EOF
{
  "metadata": {
    "title": "Mimikatz through Windows Remote Management",
    "description": "Detects usage of mimikatz through WinRM protocol by monitoring access to lsass process by wsmprovhost.exe.",
    "tags": [
      "attack.credential_access",
      "attack.execution",
      "attack.t1003",
      "attack.t1028",
      "attack.s0005"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"10\" AND winlog.event_data.TargetImage:\"C\\:\\\\windows\\\\system32\\\\lsass.exe\" AND winlog.event_data.SourceImage:\"C\\:\\\\Windows\\\\system32\\\\wsmprovhost.exe\")"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"10\" AND winlog.event_data.TargetImage:\"C\\:\\\\windows\\\\system32\\\\lsass.exe\" AND winlog.event_data.SourceImage:\"C\\:\\\\Windows\\\\system32\\\\wsmprovhost.exe\")",
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
        "subject": "Sigma Rule 'Mimikatz through Windows Remote Management'",
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
(EventID:"10" AND TargetImage:"C\:\\windows\\system32\\lsass.exe" AND SourceImage:"C\:\\Windows\\system32\\wsmprovhost.exe")
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="10" TargetImage="C:\\windows\\system32\\lsass.exe" SourceImage="C:\\Windows\\system32\\wsmprovhost.exe")
```


### logpoint
    
```
(event_id="10" TargetImage="C:\\windows\\system32\\lsass.exe" SourceImage="C:\\Windows\\system32\\wsmprovhost.exe")
```


### grep
    
```
grep -P '^(?:.*(?=.*10)(?=.*C:\windows\system32\lsass\.exe)(?=.*C:\Windows\system32\wsmprovhost\.exe))'
```



