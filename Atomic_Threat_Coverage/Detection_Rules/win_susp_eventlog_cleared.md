| Title                    | Eventlog Cleared       |
|:-------------------------|:------------------|
| **Description**          | One of the Windows Eventlogs has been cleared. e.g. caused by "wevtutil cl" command execution |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1070: Indicator Removal on Host](https://attack.mitre.org/techniques/T1070)</li><li>[T1551: None](https://attack.mitre.org/techniques/T1551)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              | <ul><li>[T1551: None](../Triggers/T1551.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://twitter.com/deviouspolack/status/832535435960209408](https://twitter.com/deviouspolack/status/832535435960209408)</li><li>[https://www.hybrid-analysis.com/sample/027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745?environmentId=100](https://www.hybrid-analysis.com/sample/027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745?environmentId=100)</li></ul>  |
| **Author**               | Florian Roth |
| Other Tags           | <ul><li>car.2016-04-002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Eventlog Cleared
id: d99b79d2-0a6f-4f46-ad8b-260b6e17f982
description: One of the Windows Eventlogs has been cleared. e.g. caused by "wevtutil cl" command execution
references:
    - https://twitter.com/deviouspolack/status/832535435960209408
    - https://www.hybrid-analysis.com/sample/027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745?environmentId=100
author: Florian Roth
date: 2017/01/10
tags:
    - attack.defense_evasion
    - attack.t1070
    - car.2016-04-002
    - attack.t1551
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 104
        Source: Microsoft-Windows-Eventlog
    condition: selection
falsepositives:
    - Unknown
level: medium

```





### powershell
    
```
Get-WinEvent -LogName System | where {($_.ID -eq "104" -and $_.message -match "Source.*Microsoft-Windows-Eventlog") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_id:"104" AND winlog.event_data.Source:"Microsoft\-Windows\-Eventlog")
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/d99b79d2-0a6f-4f46-ad8b-260b6e17f982 <<EOF
{
  "metadata": {
    "title": "Eventlog Cleared",
    "description": "One of the Windows Eventlogs has been cleared. e.g. caused by \"wevtutil cl\" command execution",
    "tags": [
      "attack.defense_evasion",
      "attack.t1070",
      "car.2016-04-002",
      "attack.t1551"
    ],
    "query": "(winlog.event_id:\"104\" AND winlog.event_data.Source:\"Microsoft\\-Windows\\-Eventlog\")"
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
                    "query": "(winlog.event_id:\"104\" AND winlog.event_data.Source:\"Microsoft\\-Windows\\-Eventlog\")",
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
        "subject": "Sigma Rule 'Eventlog Cleared'",
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
(EventID:"104" AND Source:"Microsoft\-Windows\-Eventlog")
```


### splunk
    
```
(source="WinEventLog:System" EventCode="104" Source="Microsoft-Windows-Eventlog")
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="104" Source="Microsoft-Windows-Eventlog")
```


### grep
    
```
grep -P '^(?:.*(?=.*104)(?=.*Microsoft-Windows-Eventlog))'
```



