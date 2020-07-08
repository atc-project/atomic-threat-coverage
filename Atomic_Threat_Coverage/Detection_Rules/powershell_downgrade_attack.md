| Title                    | PowerShell Downgrade Attack       |
|:-------------------------|:------------------|
| **Description**          | Detects PowerShell downgrade attack by comparing the host versions with the actually used engine version 2.0 |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Penetration Test</li><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[http://www.leeholmes.com/blog/2017/03/17/detecting-and-preventing-powershell-downgrade-attacks/](http://www.leeholmes.com/blog/2017/03/17/detecting-and-preventing-powershell-downgrade-attacks/)</li></ul>  |
| **Author**               | Florian Roth (rule), Lee Holmes (idea), Harish Segar (improvements) |
| Other Tags           | <ul><li>attack.t1059.001</li></ul> | 

## Detection Rules

### Sigma rule

```
title: PowerShell Downgrade Attack
id: 6331d09b-4785-4c13-980f-f96661356249
status: experimental
description: Detects PowerShell downgrade attack by comparing the host versions with the actually used engine version 2.0
references:
    - http://www.leeholmes.com/blog/2017/03/17/detecting-and-preventing-powershell-downgrade-attacks/
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1086
    - attack.t1059.001
author: Florian Roth (rule), Lee Holmes (idea), Harish Segar (improvements)
date: 2017/03/22
modified: 2020/03/20
logsource:
    product: windows
    service: powershell-classic
detection:
    selection:
        EventID: 400
        EngineVersion|startswith: '2.'
    filter:
        HostVersion|startswith: '2.'
    condition: selection and not filter
falsepositives:
    - Penetration Test
    - Unknown
level: medium

```





### powershell
    
```
Get-WinEvent -LogName Windows PowerShell | where {(($_.ID -eq "400" -and $_.message -match "EngineVersion.*2..*") -and  -not ($_.message -match "HostVersion.*2..*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
((winlog.event_id:"400" AND winlog.event_data.EngineVersion.keyword:2.*) AND (NOT (winlog.event_data.HostVersion.keyword:2.*)))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/6331d09b-4785-4c13-980f-f96661356249 <<EOF
{
  "metadata": {
    "title": "PowerShell Downgrade Attack",
    "description": "Detects PowerShell downgrade attack by comparing the host versions with the actually used engine version 2.0",
    "tags": [
      "attack.defense_evasion",
      "attack.execution",
      "attack.t1086",
      "attack.t1059.001"
    ],
    "query": "((winlog.event_id:\"400\" AND winlog.event_data.EngineVersion.keyword:2.*) AND (NOT (winlog.event_data.HostVersion.keyword:2.*)))"
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
                    "query": "((winlog.event_id:\"400\" AND winlog.event_data.EngineVersion.keyword:2.*) AND (NOT (winlog.event_data.HostVersion.keyword:2.*)))",
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
        "subject": "Sigma Rule 'PowerShell Downgrade Attack'",
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
((EventID:"400" AND EngineVersion.keyword:2.*) AND (NOT (HostVersion.keyword:2.*)))
```


### splunk
    
```
(source="Windows PowerShell" (EventCode="400" EngineVersion="2.*") NOT (HostVersion="2.*"))
```


### logpoint
    
```
((event_id="400" EngineVersion="2.*")  -(HostVersion="2.*"))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*400)(?=.*2\..*)))(?=.*(?!.*(?:.*(?=.*2\..*)))))'
```



