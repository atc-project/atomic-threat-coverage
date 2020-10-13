| Title                    | smbexec.py Service Installation       |
|:-------------------------|:------------------|
| **Description**          | Detects the use of smbexec.py tool by detecting a specific service installation |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1077: Windows Admin Shares](https://attack.mitre.org/techniques/T1077)</li><li>[T1021.002: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002)</li><li>[T1035: Service Execution](https://attack.mitre.org/techniques/T1035)</li><li>[T1569.002: Service Execution](https://attack.mitre.org/techniques/T1569/002)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0005_7045_windows_service_insatalled](../Data_Needed/DN_0005_7045_windows_service_insatalled.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1021.002: SMB/Windows Admin Shares](../Triggers/T1021.002.md)</li><li>[T1569.002: Service Execution](../Triggers/T1569.002.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Penetration Test</li><li>Unknown</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)</li></ul>  |
| **Author**               | Omer Faruk Celik |


## Detection Rules

### Sigma rule

```
title: smbexec.py Service Installation
id: 52a85084-6989-40c3-8f32-091e12e13f09
description: Detects the use of smbexec.py tool by detecting a specific service installation
author: Omer Faruk Celik
date: 2018/03/20
modified: 2020/08/23
references:
    - https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/
tags:
    - attack.lateral_movement
    - attack.execution
    - attack.t1077          # an old one
    - attack.t1021.002
    - attack.t1035          # an old one
    - attack.t1569.002
logsource:
    product: windows
    service: system
detection:
    service_installation:
        EventID: 7045
        ServiceName: 'BTOBTO'
        ServiceFileName: '*\execute.bat'
    condition: service_installation
fields:
    - ServiceName
    - ServiceFileName
falsepositives:
    - Penetration Test
    - Unknown
level: critical

```





### powershell
    
```
Get-WinEvent -LogName System | where {($_.ID -eq "7045" -and $_.message -match "ServiceName.*BTOBTO" -and $_.message -match "ServiceFileName.*.*\\execute.bat") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_id:"7045" AND winlog.event_data.ServiceName:"BTOBTO" AND winlog.event_data.ServiceFileName.keyword:*\\execute.bat)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/52a85084-6989-40c3-8f32-091e12e13f09 <<EOF
{
  "metadata": {
    "title": "smbexec.py Service Installation",
    "description": "Detects the use of smbexec.py tool by detecting a specific service installation",
    "tags": [
      "attack.lateral_movement",
      "attack.execution",
      "attack.t1077",
      "attack.t1021.002",
      "attack.t1035",
      "attack.t1569.002"
    ],
    "query": "(winlog.event_id:\"7045\" AND winlog.event_data.ServiceName:\"BTOBTO\" AND winlog.event_data.ServiceFileName.keyword:*\\\\execute.bat)"
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
                    "query": "(winlog.event_id:\"7045\" AND winlog.event_data.ServiceName:\"BTOBTO\" AND winlog.event_data.ServiceFileName.keyword:*\\\\execute.bat)",
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
        "subject": "Sigma Rule 'smbexec.py Service Installation'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\n    ServiceName = {{_source.ServiceName}}\nServiceFileName = {{_source.ServiceFileName}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
(EventID:"7045" AND ServiceName:"BTOBTO" AND ServiceFileName.keyword:*\\execute.bat)
```


### splunk
    
```
(source="WinEventLog:System" EventCode="7045" ServiceName="BTOBTO" ServiceFileName="*\\execute.bat") | table ServiceName,ServiceFileName
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="7045" service="BTOBTO" ServiceFileName="*\\execute.bat")
```


### grep
    
```
grep -P '^(?:.*(?=.*7045)(?=.*BTOBTO)(?=.*.*\execute\.bat))'
```



