| Title                    | SysKey Registry Keys Access       |
|:-------------------------|:------------------|
| **Description**          | Detects handle requests and access operations to specific registry keys to calculate the SysKey |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1012: Query Registry](https://attack.mitre.org/techniques/T1012)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              | <ul><li>[T1012: Query Registry](../Triggers/T1012.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/hunters-forge/ThreatHunter-Playbook/blob/master/playbooks/windows/07_discovery/T1012_query_registry/syskey_registry_keys_access.md](https://github.com/hunters-forge/ThreatHunter-Playbook/blob/master/playbooks/windows/07_discovery/T1012_query_registry/syskey_registry_keys_access.md)</li></ul>  |
| **Author**               | Roberto Rodriguez @Cyb3rWard0g |


## Detection Rules

### Sigma rule

```
title: SysKey Registry Keys Access
id: 9a4ff3b8-6187-4fd2-8e8b-e0eae1129495
description: Detects handle requests and access operations to specific registry keys to calculate the SysKey
status: experimental
date: 2019/08/12
modified: 2019/11/10
author: Roberto Rodriguez @Cyb3rWard0g
references:
    - https://github.com/hunters-forge/ThreatHunter-Playbook/blob/master/playbooks/windows/07_discovery/T1012_query_registry/syskey_registry_keys_access.md
tags:
    - attack.discovery
    - attack.t1012
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 4656
            - 4663
        ObjectType: 'key'
        ObjectName|endswith:
            - 'lsa\JD'
            - 'lsa\GBG'
            - 'lsa\Skew1'
            - 'lsa\Data'
    condition: selection
falsepositives:
    - Unknown
level: critical
```





### powershell
    
```
Get-WinEvent -LogName Security | where {(($_.ID -eq "4656" -or $_.ID -eq "4663") -and $_.message -match "ObjectType.*key" -and ($_.message -match "ObjectName.*.*lsa\\JD" -or $_.message -match "ObjectName.*.*lsa\\GBG" -or $_.message -match "ObjectName.*.*lsa\\Skew1" -or $_.message -match "ObjectName.*.*lsa\\Data")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND winlog.event_id:("4656" OR "4663") AND winlog.event_data.ObjectType:"key" AND winlog.event_data.ObjectName.keyword:(*lsa\\JD OR *lsa\\GBG OR *lsa\\Skew1 OR *lsa\\Data))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/9a4ff3b8-6187-4fd2-8e8b-e0eae1129495 <<EOF
{
  "metadata": {
    "title": "SysKey Registry Keys Access",
    "description": "Detects handle requests and access operations to specific registry keys to calculate the SysKey",
    "tags": [
      "attack.discovery",
      "attack.t1012"
    ],
    "query": "(winlog.channel:\"Security\" AND winlog.event_id:(\"4656\" OR \"4663\") AND winlog.event_data.ObjectType:\"key\" AND winlog.event_data.ObjectName.keyword:(*lsa\\\\JD OR *lsa\\\\GBG OR *lsa\\\\Skew1 OR *lsa\\\\Data))"
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
                    "query": "(winlog.channel:\"Security\" AND winlog.event_id:(\"4656\" OR \"4663\") AND winlog.event_data.ObjectType:\"key\" AND winlog.event_data.ObjectName.keyword:(*lsa\\\\JD OR *lsa\\\\GBG OR *lsa\\\\Skew1 OR *lsa\\\\Data))",
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
        "subject": "Sigma Rule 'SysKey Registry Keys Access'",
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
(EventID:("4656" "4663") AND ObjectType:"key" AND ObjectName.keyword:(*lsa\\JD *lsa\\GBG *lsa\\Skew1 *lsa\\Data))
```


### splunk
    
```
(source="WinEventLog:Security" (EventCode="4656" OR EventCode="4663") ObjectType="key" (ObjectName="*lsa\\JD" OR ObjectName="*lsa\\GBG" OR ObjectName="*lsa\\Skew1" OR ObjectName="*lsa\\Data"))
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id IN ["4656", "4663"] ObjectType="key" ObjectName IN ["*lsa\\JD", "*lsa\\GBG", "*lsa\\Skew1", "*lsa\\Data"])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*4656|.*4663))(?=.*key)(?=.*(?:.*.*lsa\JD|.*.*lsa\GBG|.*.*lsa\Skew1|.*.*lsa\Data)))'
```



