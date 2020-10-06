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

```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/619b020f-0fd7-4f23-87db-3f51ef837a34 <<EOF\n{\n  "metadata": {\n    "title": "Enumeration via the Global Catalog",\n    "description": "Detects enumeration of the global catalog (that can be performed using BloodHound or others AD reconnaissance tools). Adjust Treshhold according to domain width.",\n    "tags": [\n      "attack.discovery",\n      "attack.t1087",\n      "attack.t1087.002"\n    ],\n    "query": "(winlog.event_id:\\"5156\\" AND winlog.event_data.DestinationPort:(\\"3268\\" OR \\"3269\\"))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "1h"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.event_id:\\"5156\\" AND winlog.event_data.DestinationPort:(\\"3268\\" OR \\"3269\\"))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          },\n          "aggs": {\n            "by": {\n              "terms": {\n                "field": "SourceAddress",\n                "size": 10,\n                "order": {\n                  "_count": "desc"\n                },\n                "min_doc_count": 2001\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.aggregations.by.buckets.0.doc_count": {\n        "gt": 2000\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Enumeration via the Global Catalog\'",\n        "body": "Hits:\\n{{#aggregations.by.buckets}}\\n {{key}} {{doc_count}}\\n{{/aggregations.by.buckets}}\\n",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```

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



