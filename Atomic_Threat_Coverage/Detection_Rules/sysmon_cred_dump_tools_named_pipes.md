| Title                    | Cred Dump-Tools Named Pipes       |
|:-------------------------|:------------------|
| **Description**          | Detects well-known credential dumping tools execution via specific named pipes |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1003: OS Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              | <ul><li>[T1003: OS Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Legitimate Administrator using tool for password recovery</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment](https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment)</li></ul>  |
| **Author**               | Teymur Kheirkhabarov, oscd.community |
| Other Tags           | <ul><li>attack.t1003.002</li><li>attack.t1003.004</li><li>attack.t1003.006</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Cred Dump-Tools Named Pipes
id: 961d0ba2-3eea-4303-a930-2cf78bbfcc5e
description: Detects well-known credential dumping tools execution via specific named pipes
author: Teymur Kheirkhabarov, oscd.community
date: 2019/11/01
references:
    - https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment
tags:
    - attack.credential_access
    - attack.t1003
    - attack.t1003.002
    - attack.t1003.004
    - attack.t1003.006
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 17
        PipeName|contains:
            - '\lsadump'
            - '\cachedump'
            - '\wceservicepipe'
    condition: selection
falsepositives:
    - Legitimate Administrator using tool for password recovery
level: critical
status: experimental

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "17" -and ($_.message -match "PipeName.*.*\\lsadump.*" -or $_.message -match "PipeName.*.*\\cachedump.*" -or $_.message -match "PipeName.*.*\\wceservicepipe.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND winlog.event_id:"17" AND winlog.event_data.PipeName.keyword:(*\\lsadump* OR *\\cachedump* OR *\\wceservicepipe*))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/961d0ba2-3eea-4303-a930-2cf78bbfcc5e <<EOF
{
  "metadata": {
    "title": "Cred Dump-Tools Named Pipes",
    "description": "Detects well-known credential dumping tools execution via specific named pipes",
    "tags": [
      "attack.credential_access",
      "attack.t1003",
      "attack.t1003.002",
      "attack.t1003.004",
      "attack.t1003.006"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"17\" AND winlog.event_data.PipeName.keyword:(*\\\\lsadump* OR *\\\\cachedump* OR *\\\\wceservicepipe*))"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"17\" AND winlog.event_data.PipeName.keyword:(*\\\\lsadump* OR *\\\\cachedump* OR *\\\\wceservicepipe*))",
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
        "subject": "Sigma Rule 'Cred Dump-Tools Named Pipes'",
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
(EventID:"17" AND PipeName.keyword:(*\\lsadump* *\\cachedump* *\\wceservicepipe*))
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="17" (PipeName="*\\lsadump*" OR PipeName="*\\cachedump*" OR PipeName="*\\wceservicepipe*"))
```


### logpoint
    
```
(event_id="17" PipeName IN ["*\\lsadump*", "*\\cachedump*", "*\\wceservicepipe*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*17)(?=.*(?:.*.*\lsadump.*|.*.*\cachedump.*|.*.*\wceservicepipe.*)))'
```



