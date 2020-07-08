| Title                    | PowerShell Create Local User       |
|:-------------------------|:------------------|
| **Description**          | Detects creation of a local user via PowerShell |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li><li>[T1136: Create Account](https://attack.mitre.org/techniques/T1136)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Legitimate user creation</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1136/T1136.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1136/T1136.md)</li></ul>  |
| **Author**               | @ROxPinTeddy |
| Other Tags           | <ul><li>attack.t1059.001</li></ul> | 

## Detection Rules

### Sigma rule

```
title: PowerShell Create Local User
id: 243de76f-4725-4f2e-8225-a8a69b15ad61
status: experimental
description: Detects creation of a local user via PowerShell
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1136/T1136.md
tags:
    - attack.execution
    - attack.t1086
    - attack.persistence
    - attack.t1136
    - attack.t1059.001
author: '@ROxPinTeddy'
date: 2020/04/11
logsource:
    product: windows
    service: powershell
detection:
    selection:
        EventID: 4104
        Message|contains:
            - 'New-LocalUser'
    condition: selection
falsepositives:
    - Legitimate user creation
level: medium

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {($_.ID -eq "4104" -and ($_.message -match "Message.*.*New-LocalUser.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_id:"4104" AND Message.keyword:(*New\-LocalUser*))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/243de76f-4725-4f2e-8225-a8a69b15ad61 <<EOF
{
  "metadata": {
    "title": "PowerShell Create Local User",
    "description": "Detects creation of a local user via PowerShell",
    "tags": [
      "attack.execution",
      "attack.t1086",
      "attack.persistence",
      "attack.t1136",
      "attack.t1059.001"
    ],
    "query": "(winlog.event_id:\"4104\" AND Message.keyword:(*New\\-LocalUser*))"
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
                    "query": "(winlog.event_id:\"4104\" AND Message.keyword:(*New\\-LocalUser*))",
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
        "subject": "Sigma Rule 'PowerShell Create Local User'",
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
(EventID:"4104" AND Message.keyword:(*New\-LocalUser*))
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="4104" (Message="*New-LocalUser*"))
```


### logpoint
    
```
(event_id="4104" Message IN ["*New-LocalUser*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*4104)(?=.*(?:.*.*New-LocalUser.*)))'
```



