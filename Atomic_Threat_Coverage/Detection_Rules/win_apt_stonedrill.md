| Title                    | StoneDrill Service Install       |
|:-------------------------|:------------------|
| **Description**          | This method detects a service install of the malicious Microsoft Network Realtime Inspection Service service described in StoneDrill report by Kaspersky |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1050: New Service](https://attack.mitre.org/techniques/T1050)</li><li>[T1543.003: Windows Service](https://attack.mitre.org/techniques/T1543/003)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0005_7045_windows_service_insatalled](../Data_Needed/DN_0005_7045_windows_service_insatalled.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1543.003: Windows Service](../Triggers/T1543.003.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unlikely</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://securelist.com/blog/research/77725/from-shamoon-to-stonedrill/](https://securelist.com/blog/research/77725/from-shamoon-to-stonedrill/)</li></ul>  |
| **Author**               | Florian Roth |
| Other Tags           | <ul><li>attack.g0064</li></ul> | 

## Detection Rules

### Sigma rule

```
title: StoneDrill Service Install
id: 9e987c6c-4c1e-40d8-bd85-dd26fba8fdd6
description: This method detects a service install of the malicious Microsoft Network Realtime Inspection Service service described in StoneDrill report by Kaspersky
author: Florian Roth
date: 2017/03/07
references:
    - https://securelist.com/blog/research/77725/from-shamoon-to-stonedrill/
tags:
    - attack.persistence
    - attack.g0064
    - attack.t1050          # an old one
    - attack.t1543.003
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 7045
        ServiceName: NtsSrv
        ServiceFileName: '* LocalService'
    condition: selection
falsepositives:
    - Unlikely
level: high

```





### powershell
    
```
Get-WinEvent -LogName System | where {($_.ID -eq "7045" -and $_.message -match "ServiceName.*NtsSrv" -and $_.message -match "ServiceFileName.*.* LocalService") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_id:"7045" AND winlog.event_data.ServiceName:"NtsSrv" AND winlog.event_data.ServiceFileName.keyword:*\ LocalService)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/9e987c6c-4c1e-40d8-bd85-dd26fba8fdd6 <<EOF
{
  "metadata": {
    "title": "StoneDrill Service Install",
    "description": "This method detects a service install of the malicious Microsoft Network Realtime Inspection Service service described in StoneDrill report by Kaspersky",
    "tags": [
      "attack.persistence",
      "attack.g0064",
      "attack.t1050",
      "attack.t1543.003"
    ],
    "query": "(winlog.event_id:\"7045\" AND winlog.event_data.ServiceName:\"NtsSrv\" AND winlog.event_data.ServiceFileName.keyword:*\\ LocalService)"
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
                    "query": "(winlog.event_id:\"7045\" AND winlog.event_data.ServiceName:\"NtsSrv\" AND winlog.event_data.ServiceFileName.keyword:*\\ LocalService)",
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
        "subject": "Sigma Rule 'StoneDrill Service Install'",
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
(EventID:"7045" AND ServiceName:"NtsSrv" AND ServiceFileName.keyword:* LocalService)
```


### splunk
    
```
(source="WinEventLog:System" EventCode="7045" ServiceName="NtsSrv" ServiceFileName="* LocalService")
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="7045" service="NtsSrv" ServiceFileName="* LocalService")
```


### grep
    
```
grep -P '^(?:.*(?=.*7045)(?=.*NtsSrv)(?=.*.* LocalService))'
```



