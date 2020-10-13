| Title                    | Rare Schtasks Creations       |
|:-------------------------|:------------------|
| **Description**          | Detects rare scheduled tasks creations that only appear a few times per time frame and could reveal password dumpers, backdoor installs or other types of malicious code |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1053: Scheduled Task/Job](https://attack.mitre.org/techniques/T1053)</li><li>[T1053.005: Scheduled Task](https://attack.mitre.org/techniques/T1053/005)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0064_4698_scheduled_task_was_created](../Data_Needed/DN_0064_4698_scheduled_task_was_created.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1053.005: Scheduled Task](../Triggers/T1053.005.md)</li></ul>  |
| **Severity Level**       | low |
| **False Positives**      | <ul><li>Software installation</li><li>Software updates</li></ul>  |
| **Development Status**   | experimental |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Florian Roth |
| Other Tags           | <ul><li>car.2013-08-001</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Rare Schtasks Creations
id: b0d77106-7bb0-41fe-bd94-d1752164d066
description: Detects rare scheduled tasks creations that only appear a few times per time frame and could reveal password dumpers, backdoor installs or other types of malicious code
status: experimental
author: Florian Roth
date: 2017/03/23
tags:
    - attack.execution
    - attack.privilege_escalation
    - attack.persistence
    - attack.t1053           # an old one
    - car.2013-08-001
    - attack.t1053.005
logsource:
    product: windows
    service: security
    definition: 'The Advanced Audit Policy setting Object Access > Audit Other Object Access Events has to be configured to allow this detection (not in the baseline recommendations by Microsoft). We also recommend extracting the Command field from the embedded XML in the event data.'
detection:
    selection:
        EventID: 4698
    timeframe: 7d
    condition: selection | count() by TaskName < 5
falsepositives:
    - Software installation
    - Software updates
level: low

```





### powershell
    
```
Get-WinEvent -LogName Security | where {($_.ID -eq "4698") }  | group-object TaskName | where { $_.count -lt 5 } | select name,count | sort -desc
```


### es-qs
    
```
An unsupported feature is required for this Sigma rule (detection_rules/sigma/rules/windows/builtin/win_rare_schtasks_creations.yml): Aggregations not implemented for this backend
Feel free to contribute for fun and fame, this is open source :) -> https://github.com/Neo23x0/sigma
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/b0d77106-7bb0-41fe-bd94-d1752164d066 <<EOF
{
  "metadata": {
    "title": "Rare Schtasks Creations",
    "description": "Detects rare scheduled tasks creations that only appear a few times per time frame and could reveal password dumpers, backdoor installs or other types of malicious code",
    "tags": [
      "attack.execution",
      "attack.privilege_escalation",
      "attack.persistence",
      "attack.t1053",
      "car.2013-08-001",
      "attack.t1053.005"
    ],
    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"4698\")"
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
                    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"4698\")",
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
                "field": "TaskName",
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
        "subject": "Sigma Rule 'Rare Schtasks Creations'",
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
An unsupported feature is required for this Sigma rule (detection_rules/sigma/rules/windows/builtin/win_rare_schtasks_creations.yml): Aggregations not implemented for this backend
Feel free to contribute for fun and fame, this is open source :) -> https://github.com/Neo23x0/sigma
```


### splunk
    
```
(source="WinEventLog:Security" EventCode="4698") | eventstats count as val by TaskName| search val < 5
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="4698") | chart count() as val by TaskName | search val < 5
```


### grep
    
```
grep -P '^4698'
```



