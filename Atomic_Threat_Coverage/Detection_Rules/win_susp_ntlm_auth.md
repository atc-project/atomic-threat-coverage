| Title                    | NTLM Logon       |
|:-------------------------|:------------------|
| **Description**          | Detects logons using NTLM, which could be caused by a legacy source or attackers |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1075: Pass the Hash](https://attack.mitre.org/techniques/T1075)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | low |
| **False Positives**      | <ul><li>Legacy hosts</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://twitter.com/JohnLaTwC/status/1004895028995477505](https://twitter.com/JohnLaTwC/status/1004895028995477505)</li><li>[https://goo.gl/PsqrhT](https://goo.gl/PsqrhT)</li></ul>  |
| **Author**               | Florian Roth |
| Other Tags           | <ul><li>attack.t1550.002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: NTLM Logon
id: 98c3bcf1-56f2-49dc-9d8d-c66cf190238b
status: experimental
description: Detects logons using NTLM, which could be caused by a legacy source or attackers
references:
    - https://twitter.com/JohnLaTwC/status/1004895028995477505
    - https://goo.gl/PsqrhT
author: Florian Roth
date: 2018/06/08
tags:
    - attack.lateral_movement
    - attack.t1075
    - attack.t1550.002
logsource:
    product: windows
    service: ntlm
    definition: Reqiures events from Microsoft-Windows-NTLM/Operational
detection:
    selection:
        EventID: 8002
        CallingProcessName: '*'  # We use this to avoid false positives with ID 8002 on other log sources if the logsource isn't set correctly
    condition: selection
falsepositives:
    - Legacy hosts
level: low

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-NTLM/Operational | where {($_.ID -eq "8002" -and $_.message -match "CallingProcessName.*.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-NTLM\/Operational" AND winlog.event_id:"8002" AND winlog.event_data.CallingProcessName.keyword:*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/98c3bcf1-56f2-49dc-9d8d-c66cf190238b <<EOF
{
  "metadata": {
    "title": "NTLM Logon",
    "description": "Detects logons using NTLM, which could be caused by a legacy source or attackers",
    "tags": [
      "attack.lateral_movement",
      "attack.t1075",
      "attack.t1550.002"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-NTLM\\/Operational\" AND winlog.event_id:\"8002\" AND winlog.event_data.CallingProcessName.keyword:*)"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-NTLM\\/Operational\" AND winlog.event_id:\"8002\" AND winlog.event_data.CallingProcessName.keyword:*)",
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
        "subject": "Sigma Rule 'NTLM Logon'",
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
(EventID:"8002" AND CallingProcessName.keyword:*)
```


### splunk
    
```
(source="Microsoft-Windows-NTLM/Operational" EventCode="8002" CallingProcessName="*")
```


### logpoint
    
```
(event_source="Microsoft-Windows-NTLM/Operational" event_id="8002" CallingProcessName="*")
```


### grep
    
```
grep -P '^(?:.*(?=.*8002)(?=.*.*))'
```



