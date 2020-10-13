| Title                    | Enumeration via the Global Catalog       |
|:-------------------------|:------------------|
| **Description**          | Detects enumeration of the global catalog (that can be performed using BloodHound or others AD reconnaissance tools). Adjust Treshhold according to domain width. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1087: Account Discovery](https://attack.mitre.org/techniques/T1087)</li><li>[T1087.002: Domain Account](https://attack.mitre.org/techniques/T1087/002)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              | <ul><li>[T1087.002: Domain Account](../Triggers/T1087.002.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Exclude known DCs.</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Chakib Gzenayi (@Chak092), Hosni Mribah |


## Detection Rules

### Sigma rule

```
title: Enumeration via the Global Catalog 
description: Detects enumeration of the global catalog (that can be performed using BloodHound or others AD reconnaissance tools). Adjust Treshhold according to domain width.
author: Chakib Gzenayi (@Chak092), Hosni Mribah
id: 619b020f-0fd7-4f23-87db-3f51ef837a34
date: 2020/05/11
modified: 2020/08/23
tags:
    - attack.discovery
    - attack.t1087          # an old one
    - attack.t1087.002
logsource:
    product: windows
    service: system
    definition: 'The advanced audit policy setting "Windows Filtering Platform > Filtering Platform Connection" must be configured for Success'
detection:
    selection:
        EventID: 5156
        DestinationPort:
        - 3268
        - 3269
    timeframe: 1h
    condition: selection | count() by SourceAddress > 2000
falsepositives:
    - Exclude known DCs.
level: medium

```





### powershell
    
```
Get-WinEvent -LogName System | where {($_.ID -eq "5156" -and ($_.message -match "3268" -or $_.message -match "3269")) }  | group-object SourceAddress | where { $_.count -gt 2000 } | select name,count | sort -desc
```


### es-qs
    
```
An unsupported feature is required for this Sigma rule (detection_rules/sigma/rules/windows/builtin/win_global_catalog_enumeration.yml): Aggregations not implemented for this backend
Feel free to contribute for fun and fame, this is open source :) -> https://github.com/Neo23x0/sigma
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/619b020f-0fd7-4f23-87db-3f51ef837a34 <<EOF
{
  "metadata": {
    "title": "Enumeration via the Global Catalog",
    "description": "Detects enumeration of the global catalog (that can be performed using BloodHound or others AD reconnaissance tools). Adjust Treshhold according to domain width.",
    "tags": [
      "attack.discovery",
      "attack.t1087",
      "attack.t1087.002"
    ],
    "query": "(winlog.event_id:\"5156\" AND winlog.event_data.DestinationPort:(\"3268\" OR \"3269\"))"
  },
  "trigger": {
    "schedule": {
      "interval": "1h"
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
                    "query": "(winlog.event_id:\"5156\" AND winlog.event_data.DestinationPort:(\"3268\" OR \"3269\"))",
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
                "field": "SourceAddress",
                "size": 10,
                "order": {
                  "_count": "desc"
                },
                "min_doc_count": 2001
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
        "gt": 2000
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
        "subject": "Sigma Rule 'Enumeration via the Global Catalog'",
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
An unsupported feature is required for this Sigma rule (detection_rules/sigma/rules/windows/builtin/win_global_catalog_enumeration.yml): Aggregations not implemented for this backend
Feel free to contribute for fun and fame, this is open source :) -> https://github.com/Neo23x0/sigma
```


### splunk
    
```
(source="WinEventLog:System" EventCode="5156" (DestinationPort="3268" OR DestinationPort="3269")) | eventstats count as val by SourceAddress| search val > 2000
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="5156" DestinationPort IN ["3268", "3269"]) | chart count() as val by SourceAddress | search val > 2000
```


### grep
    
```
grep -P '^(?:.*(?=.*5156)(?=.*(?:.*3268|.*3269)))'
```



