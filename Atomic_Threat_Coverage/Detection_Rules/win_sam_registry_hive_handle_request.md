| Title                    | SAM Registry Hive Handle Request       |
|:-------------------------|:------------------|
| **Description**          | Detects handles requested to SAM registry hive |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1012: Query Registry](https://attack.mitre.org/techniques/T1012)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              | <ul><li>[T1012: Query Registry](../Triggers/T1012.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/07_discovery/T1012_query_registry/sam_registry_hive_access.md](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/07_discovery/T1012_query_registry/sam_registry_hive_access.md)</li></ul>  |
| **Author**               | Roberto Rodriguez @Cyb3rWard0g |


## Detection Rules

### Sigma rule

```
title: SAM Registry Hive Handle Request
id: f8748f2c-89dc-4d95-afb0-5a2dfdbad332
description: Detects handles requested to SAM registry hive
status: experimental
date: 2019/08/12
modified: 2019/11/10
author: Roberto Rodriguez @Cyb3rWard0g
references:
    - https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/07_discovery/T1012_query_registry/sam_registry_hive_access.md
tags:
    - attack.discovery
    - attack.t1012
logsource:
    product: windows
    service: security
detection:
    selection: 
        EventID: 4656
        ObjectType: 'Key'
        ObjectName|endswith: '\SAM'
    condition: selection
fields:
    - ComputerName
    - SubjectDomainName
    - SubjectUserName
    - ProcessName
    - ObjectName
falsepositives:
    - Unknown
level: critical

```





### powershell
    
```
Get-WinEvent -LogName Security | where {($_.ID -eq "4656" -and $_.message -match "ObjectType.*Key" -and $_.message -match "ObjectName.*.*\\SAM") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND winlog.event_id:"4656" AND winlog.event_data.ObjectType:"Key" AND winlog.event_data.ObjectName.keyword:*\\SAM)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/f8748f2c-89dc-4d95-afb0-5a2dfdbad332 <<EOF
{
  "metadata": {
    "title": "SAM Registry Hive Handle Request",
    "description": "Detects handles requested to SAM registry hive",
    "tags": [
      "attack.discovery",
      "attack.t1012"
    ],
    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"4656\" AND winlog.event_data.ObjectType:\"Key\" AND winlog.event_data.ObjectName.keyword:*\\\\SAM)"
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
                    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"4656\" AND winlog.event_data.ObjectType:\"Key\" AND winlog.event_data.ObjectName.keyword:*\\\\SAM)",
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
        "subject": "Sigma Rule 'SAM Registry Hive Handle Request'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\n     ComputerName = {{_source.ComputerName}}\nSubjectDomainName = {{_source.SubjectDomainName}}\n  SubjectUserName = {{_source.SubjectUserName}}\n      ProcessName = {{_source.ProcessName}}\n       ObjectName = {{_source.ObjectName}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
(EventID:"4656" AND ObjectType:"Key" AND ObjectName.keyword:*\\SAM)
```


### splunk
    
```
(source="WinEventLog:Security" EventCode="4656" ObjectType="Key" ObjectName="*\\SAM") | table ComputerName,SubjectDomainName,SubjectUserName,ProcessName,ObjectName
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="4656" ObjectType="Key" ObjectName="*\\SAM")
```


### grep
    
```
grep -P '^(?:.*(?=.*4656)(?=.*Key)(?=.*.*\SAM))'
```



