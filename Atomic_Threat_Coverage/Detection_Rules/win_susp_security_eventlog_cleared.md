| Title                    | Security Eventlog Cleared       |
|:-------------------------|:------------------|
| **Description**          | Some threat groups tend to delete the local 'Security' Eventlog using certain utitlities |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1070: Indicator Removal on Host](https://attack.mitre.org/techniques/T1070)</li><li>[T1070.001: Clear Windows Event Logs](https://attack.mitre.org/techniques/T1070/001)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0050_1102_audit_log_was_cleared](../Data_Needed/DN_0050_1102_audit_log_was_cleared.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1070: Indicator Removal on Host](../Triggers/T1070.md)</li><li>[T1070.001: Clear Windows Event Logs](../Triggers/T1070.001.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Rollout of log collection agents (the setup routine often includes a reset of the local Eventlog)</li><li>System provisioning (system reset before the golden image creation)</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Florian Roth |
| Other Tags           | <ul><li>car.2016-04-002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Security Eventlog Cleared
id: f2f01843-e7b8-4f95-a35a-d23584476423
description: Some threat groups tend to delete the local 'Security' Eventlog using certain utitlities
tags:
    - attack.defense_evasion
    - attack.t1070          # an old one
    - attack.t1070.001
    - car.2016-04-002
author: Florian Roth
date: 2017/02/19
modified: 2020/08/23
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 517
            - 1102
    condition: selection
falsepositives:
    - Rollout of log collection agents (the setup routine often includes a reset of the local Eventlog)
    - System provisioning (system reset before the golden image creation)
level: high

```





### powershell
    
```
Get-WinEvent -LogName Security | where {(($_.ID -eq "517" -or $_.ID -eq "1102")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND winlog.event_id:("517" OR "1102"))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/f2f01843-e7b8-4f95-a35a-d23584476423 <<EOF
{
  "metadata": {
    "title": "Security Eventlog Cleared",
    "description": "Some threat groups tend to delete the local 'Security' Eventlog using certain utitlities",
    "tags": [
      "attack.defense_evasion",
      "attack.t1070",
      "attack.t1070.001",
      "car.2016-04-002"
    ],
    "query": "(winlog.channel:\"Security\" AND winlog.event_id:(\"517\" OR \"1102\"))"
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
                    "query": "(winlog.channel:\"Security\" AND winlog.event_id:(\"517\" OR \"1102\"))",
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
        "subject": "Sigma Rule 'Security Eventlog Cleared'",
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
EventID:("517" "1102")
```


### splunk
    
```
(source="WinEventLog:Security" (EventCode="517" OR EventCode="1102"))
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id IN ["517", "1102"])
```


### grep
    
```
grep -P '^(?:.*517|.*1102)'
```



