| Title                    | PowerShell Called from an Executable Version Mismatch       |
|:-------------------------|:------------------|
| **Description**          | Detects PowerShell called from an executable by the version mismatch method |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Penetration Tests</li><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://adsecurity.org/?p=2921](https://adsecurity.org/?p=2921)</li></ul>  |
| **Author**               | Sean Metcalf (source), Florian Roth (rule) |
| Other Tags           | <ul><li>attack.t1059.001</li></ul> | 

## Detection Rules

### Sigma rule

```
title: PowerShell Called from an Executable Version Mismatch
id: c70e019b-1479-4b65-b0cc-cd0c6093a599
status: experimental
description: Detects PowerShell called from an executable by the version mismatch method
references:
    - https://adsecurity.org/?p=2921
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1086
    - attack.t1059.001
author: Sean Metcalf (source), Florian Roth (rule)
date: 2017/03/05
logsource:
    product: windows
    service: powershell-classic
detection:
    selection1:
        EventID: 400
        EngineVersion:
            - '2.*'
            - '4.*'
            - '5.*'
        HostVersion: '3.*'
    condition: selection1
falsepositives:
    - Penetration Tests
    - Unknown
level: high

```





### powershell
    
```
Get-WinEvent -LogName Windows PowerShell | where {($_.ID -eq "400" -and ($_.message -match "EngineVersion.*2..*" -or $_.message -match "EngineVersion.*4..*" -or $_.message -match "EngineVersion.*5..*") -and $_.message -match "HostVersion.*3..*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_id:"400" AND winlog.event_data.EngineVersion.keyword:(2.* OR 4.* OR 5.*) AND winlog.event_data.HostVersion.keyword:3.*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/c70e019b-1479-4b65-b0cc-cd0c6093a599 <<EOF
{
  "metadata": {
    "title": "PowerShell Called from an Executable Version Mismatch",
    "description": "Detects PowerShell called from an executable by the version mismatch method",
    "tags": [
      "attack.defense_evasion",
      "attack.execution",
      "attack.t1086",
      "attack.t1059.001"
    ],
    "query": "(winlog.event_id:\"400\" AND winlog.event_data.EngineVersion.keyword:(2.* OR 4.* OR 5.*) AND winlog.event_data.HostVersion.keyword:3.*)"
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
                    "query": "(winlog.event_id:\"400\" AND winlog.event_data.EngineVersion.keyword:(2.* OR 4.* OR 5.*) AND winlog.event_data.HostVersion.keyword:3.*)",
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
        "subject": "Sigma Rule 'PowerShell Called from an Executable Version Mismatch'",
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
(EventID:"400" AND EngineVersion.keyword:(2.* 4.* 5.*) AND HostVersion.keyword:3.*)
```


### splunk
    
```
(source="Windows PowerShell" EventCode="400" (EngineVersion="2.*" OR EngineVersion="4.*" OR EngineVersion="5.*") HostVersion="3.*")
```


### logpoint
    
```
(event_id="400" EngineVersion IN ["2.*", "4.*", "5.*"] HostVersion="3.*")
```


### grep
    
```
grep -P '^(?:.*(?=.*400)(?=.*(?:.*2\..*|.*4\..*|.*5\..*))(?=.*3\..*))'
```



