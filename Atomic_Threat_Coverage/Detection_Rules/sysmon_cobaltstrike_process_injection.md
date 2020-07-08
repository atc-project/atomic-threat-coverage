| Title                    | CobaltStrike Process Injection       |
|:-------------------------|:------------------|
| **Description**          | Detects a possible remote threat creation with certain characteristics which are typical for Cobalt Strike beacons |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1055: Process Injection](https://attack.mitre.org/techniques/T1055)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              | <ul><li>[T1055: Process Injection](../Triggers/T1055.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://medium.com/@olafhartong/cobalt-strike-remote-threads-detection-206372d11d0f](https://medium.com/@olafhartong/cobalt-strike-remote-threads-detection-206372d11d0f)</li><li>[https://blog.cobaltstrike.com/2018/04/09/cobalt-strike-3-11-the-snake-that-eats-its-tail/](https://blog.cobaltstrike.com/2018/04/09/cobalt-strike-3-11-the-snake-that-eats-its-tail/)</li></ul>  |
| **Author**               | Olaf Hartong, Florian Roth, Aleksey Potapov, oscd.community |


## Detection Rules

### Sigma rule

```
title: CobaltStrike Process Injection
id: 6309645e-122d-4c5b-bb2b-22e4f9c2fa42
description: Detects a possible remote threat creation with certain characteristics which are typical for Cobalt Strike beacons
references:
    - https://medium.com/@olafhartong/cobalt-strike-remote-threads-detection-206372d11d0f
    - https://blog.cobaltstrike.com/2018/04/09/cobalt-strike-3-11-the-snake-that-eats-its-tail/
tags:
    - attack.defense_evasion
    - attack.t1055
status: experimental
author: Olaf Hartong, Florian Roth, Aleksey Potapov, oscd.community
date: 2018/11/30
modified: 2019/11/08
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 8
        TargetProcessAddress|endswith: 
            - '0B80'
            - '0C7C'
            - '0C88'
    condition: selection
falsepositives:
    - unknown
level: high


```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "8" -and ($_.message -match "TargetProcessAddress.*.*0B80" -or $_.message -match "TargetProcessAddress.*.*0C7C" -or $_.message -match "TargetProcessAddress.*.*0C88")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND winlog.event_id:"8" AND TargetProcessAddress.keyword:(*0B80 OR *0C7C OR *0C88))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/6309645e-122d-4c5b-bb2b-22e4f9c2fa42 <<EOF
{
  "metadata": {
    "title": "CobaltStrike Process Injection",
    "description": "Detects a possible remote threat creation with certain characteristics which are typical for Cobalt Strike beacons",
    "tags": [
      "attack.defense_evasion",
      "attack.t1055"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"8\" AND TargetProcessAddress.keyword:(*0B80 OR *0C7C OR *0C88))"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"8\" AND TargetProcessAddress.keyword:(*0B80 OR *0C7C OR *0C88))",
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
        "subject": "Sigma Rule 'CobaltStrike Process Injection'",
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
(EventID:"8" AND TargetProcessAddress.keyword:(*0B80 *0C7C *0C88))
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="8" (TargetProcessAddress="*0B80" OR TargetProcessAddress="*0C7C" OR TargetProcessAddress="*0C88"))
```


### logpoint
    
```
(event_id="8" TargetProcessAddress IN ["*0B80", "*0C7C", "*0C88"])
```


### grep
    
```
grep -P '^(?:.*(?=.*8)(?=.*(?:.*.*0B80|.*.*0C7C|.*.*0C88)))'
```



