| Title                    | Remote PowerShell Sessions       |
|:-------------------------|:------------------|
| **Description**          | Detects basic PowerShell Remoting by monitoring for network inbound connections to ports 5985 OR 5986 |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0087_5156_windows_filtering_platform_has_permitted_connection](../Data_Needed/DN_0087_5156_windows_filtering_platform_has_permitted_connection.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Legitimate use of remote PowerShell execution</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/02_execution/T1086_powershell/powershell_remote_session.md](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/02_execution/T1086_powershell/powershell_remote_session.md)</li></ul>  |
| **Author**               | Roberto Rodriguez @Cyb3rWard0g |


## Detection Rules

### Sigma rule

```
title: Remote PowerShell Sessions
id: 13acf386-b8c6-4fe0-9a6e-c4756b974698
description: Detects basic PowerShell Remoting by monitoring for network inbound connections to ports 5985 OR 5986
status: experimental
date: 2019/09/12
author: Roberto Rodriguez @Cyb3rWard0g
references:
    - https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/02_execution/T1086_powershell/powershell_remote_session.md
tags:
    - attack.execution
    - attack.t1086
logsource:
    product: windows
    service: security
detection:
    selection: 
        EventID: 5156
        DestPort:
            - 5985
            - 5986
        LayerRTID: 44
    condition: selection
falsepositives:
    - Legitimate use of remote PowerShell execution
level: high

```





### powershell
    
```
Get-WinEvent -LogName Security | where {($_.ID -eq "5156" -and ($_.message -match "5985" -or $_.message -match "5986") -and $_.message -match "LayerRTID.*44") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND winlog.event_id:"5156" AND DestPort:("5985" OR "5986") AND LayerRTID:"44")
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/13acf386-b8c6-4fe0-9a6e-c4756b974698 <<EOF
{
  "metadata": {
    "title": "Remote PowerShell Sessions",
    "description": "Detects basic PowerShell Remoting by monitoring for network inbound connections to ports 5985 OR 5986",
    "tags": [
      "attack.execution",
      "attack.t1086"
    ],
    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"5156\" AND DestPort:(\"5985\" OR \"5986\") AND LayerRTID:\"44\")"
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
                    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"5156\" AND DestPort:(\"5985\" OR \"5986\") AND LayerRTID:\"44\")",
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
      "email": {
        "to": "root@localhost",
        "subject": "Sigma Rule 'Remote PowerShell Sessions'",
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
(EventID:"5156" AND DestPort:("5985" "5986") AND LayerRTID:"44")
```


### splunk
    
```
(source="WinEventLog:Security" EventCode="5156" (DestPort="5985" OR DestPort="5986") LayerRTID="44")
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="5156" DestPort IN ["5985", "5986"] LayerRTID="44")
```


### grep
    
```
grep -P '^(?:.*(?=.*5156)(?=.*(?:.*5985|.*5986))(?=.*44))'
```



