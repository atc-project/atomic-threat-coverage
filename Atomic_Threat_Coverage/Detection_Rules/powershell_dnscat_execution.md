| Title                    | Dnscat Execution       |
|:-------------------------|:------------------|
| **Description**          | Dnscat exfiltration tool execution |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0010: Exfiltration](https://attack.mitre.org/tactics/TA0010)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1048: Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              | <ul><li>[T1048: Exfiltration Over Alternative Protocol](../Triggers/T1048.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Legitimate usage of PowerShell Dnscat2 — DNS Exfiltration tool (unlikely)</li></ul>  |
| **Development Status**   | experimental |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Daniil Yugoslavskiy, oscd.community |


## Detection Rules

### Sigma rule

```
title: Dnscat Execution
id: a6d67db4-6220-436d-8afc-f3842fe05d43
description: Dnscat exfiltration tool execution
status: experimental
author: Daniil Yugoslavskiy, oscd.community
date: 2019/10/24
tags:
    - attack.exfiltration
    - attack.t1048
logsource:
    product: windows
    service: powershell
detection:
    selection:
        EventID: 4104
        ScriptBlockText|contains: "Start-Dnscat2"
    condition: selection
falsepositives:
    - Legitimate usage of PowerShell Dnscat2 — DNS Exfiltration tool (unlikely)
level: critical

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {($_.ID -eq "4104" -and $_.message -match "ScriptBlockText.*.*Start-Dnscat2.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_id:"4104" AND ScriptBlockText.keyword:*Start\-Dnscat2*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/a6d67db4-6220-436d-8afc-f3842fe05d43 <<EOF
{
  "metadata": {
    "title": "Dnscat Execution",
    "description": "Dnscat exfiltration tool execution",
    "tags": [
      "attack.exfiltration",
      "attack.t1048"
    ],
    "query": "(winlog.event_id:\"4104\" AND ScriptBlockText.keyword:*Start\\-Dnscat2*)"
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
                    "query": "(winlog.event_id:\"4104\" AND ScriptBlockText.keyword:*Start\\-Dnscat2*)",
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
        "subject": "Sigma Rule 'Dnscat Execution'",
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
(EventID:"4104" AND ScriptBlockText.keyword:*Start\-Dnscat2*)
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="4104" ScriptBlockText="*Start-Dnscat2*")
```


### logpoint
    
```
(event_id="4104" ScriptBlockText="*Start-Dnscat2*")
```


### grep
    
```
grep -P '^(?:.*(?=.*4104)(?=.*.*Start-Dnscat2.*))'
```



