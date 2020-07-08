| Title                    | Addition of Domain Trusts       |
|:-------------------------|:------------------|
| **Description**          | Addition of domains is seldom and should be verified for legitimacy. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Legitimate extension of domain structure</li></ul>  |
| **Development Status**   | stable |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Thomas Patzke |


## Detection Rules

### Sigma rule

```
title: Addition of Domain Trusts
id: 0255a820-e564-4e40-af2b-6ac61160335c
status: stable
description: Addition of domains is seldom and should be verified for legitimacy.
author: Thomas Patzke
date: 2019/12/03
tags:
    - attack.persistence
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4706
    condition: selection
falsepositives:
    - Legitimate extension of domain structure
level: medium

```





### powershell
    
```
Get-WinEvent -LogName Security | where {($_.ID -eq "4706") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND winlog.event_id:"4706")
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/0255a820-e564-4e40-af2b-6ac61160335c <<EOF
{
  "metadata": {
    "title": "Addition of Domain Trusts",
    "description": "Addition of domains is seldom and should be verified for legitimacy.",
    "tags": [
      "attack.persistence"
    ],
    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"4706\")"
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
                    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"4706\")",
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
        "subject": "Sigma Rule 'Addition of Domain Trusts'",
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
EventID:"4706"
```


### splunk
    
```
(source="WinEventLog:Security" EventCode="4706")
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="4706")
```


### grep
    
```
grep -P '^4706'
```



