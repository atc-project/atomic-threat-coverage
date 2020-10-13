| Title                    | Rare Service Installs       |
|:-------------------------|:------------------|
| **Description**          | Detects rare service installs that only appear a few times per time frame and could reveal password dumpers, backdoor installs or other types of malicious services |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1050: New Service](https://attack.mitre.org/techniques/T1050)</li><li>[T1543.003: Windows Service](https://attack.mitre.org/techniques/T1543/003)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0005_7045_windows_service_insatalled](../Data_Needed/DN_0005_7045_windows_service_insatalled.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1543.003: Windows Service](../Triggers/T1543.003.md)</li></ul>  |
| **Severity Level**       | low |
| **False Positives**      | <ul><li>Software installation</li><li>Software updates</li></ul>  |
| **Development Status**   | experimental |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Florian Roth |
| Other Tags           | <ul><li>car.2013-09-005</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Rare Service Installs
id: 66bfef30-22a5-4fcd-ad44-8d81e60922ae
description: Detects rare service installs that only appear a few times per time frame and could reveal password dumpers, backdoor installs or other types of malicious services
status: experimental
author: Florian Roth
date: 2017/03/08
tags:
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1050          # an old one
    - car.2013-09-005
    - attack.t1543.003
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 7045
    timeframe: 7d
    condition: selection | count() by ServiceFileName < 5
falsepositives:
    - Software installation
    - Software updates
level: low

```





### powershell
    
```
Get-WinEvent -LogName System | where {($_.ID -eq "7045") }  | group-object ServiceFileName | where { $_.count -lt 5 } | select name,count | sort -desc
```


### es-qs
    
```
An unsupported feature is required for this Sigma rule (detection_rules/sigma/rules/windows/builtin/win_rare_service_installs.yml): Aggregations not implemented for this backend
Feel free to contribute for fun and fame, this is open source :) -> https://github.com/Neo23x0/sigma
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/66bfef30-22a5-4fcd-ad44-8d81e60922ae <<EOF
{
  "metadata": {
    "title": "Rare Service Installs",
    "description": "Detects rare service installs that only appear a few times per time frame and could reveal password dumpers, backdoor installs or other types of malicious services",
    "tags": [
      "attack.persistence",
      "attack.privilege_escalation",
      "attack.t1050",
      "car.2013-09-005",
      "attack.t1543.003"
    ],
    "query": "winlog.event_id:\"7045\""
  },
  "trigger": {
    "schedule": {
      "interval": "7d"
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
                    "query": "winlog.event_id:\"7045\"",
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
          },
          "aggs": {
            "by": {
              "terms": {
                "field": "winlog.event_data.ServiceFileName",
                "size": 10,
                "order": {
                  "_count": "asc"
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
      "ctx.payload.aggregations.by.buckets.0.doc_count": {
        "lt": 5
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
        "subject": "Sigma Rule 'Rare Service Installs'",
        "body": "Hits:\n{{#aggregations.by.buckets}}\n {{key}} {{doc_count}}\n{{/aggregations.by.buckets}}\n",
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
An unsupported feature is required for this Sigma rule (detection_rules/sigma/rules/windows/builtin/win_rare_service_installs.yml): Aggregations not implemented for this backend
Feel free to contribute for fun and fame, this is open source :) -> https://github.com/Neo23x0/sigma
```


### splunk
    
```
(source="WinEventLog:System" EventCode="7045") | eventstats count as val by ServiceFileName| search val < 5
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="7045") | chart count() as val by ServiceFileName | search val < 5
```


### grep
    
```
grep -P '^7045'
```



