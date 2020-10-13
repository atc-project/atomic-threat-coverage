| Title                    | PowerShell Credential Prompt       |
|:-------------------------|:------------------|
| **Description**          | Detects PowerShell calling a credential prompt |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1059.001: PowerShell](https://attack.mitre.org/techniques/T1059/001)</li><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0036_4104_windows_powershell_script_block](../Data_Needed/DN_0036_4104_windows_powershell_script_block.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1059.001: PowerShell](../Triggers/T1059.001.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://twitter.com/JohnLaTwC/status/850381440629981184](https://twitter.com/JohnLaTwC/status/850381440629981184)</li><li>[https://t.co/ezOTGy1a1G](https://t.co/ezOTGy1a1G)</li></ul>  |
| **Author**               | John Lambert (idea), Florian Roth (rule) |


## Detection Rules

### Sigma rule

```
title: PowerShell Credential Prompt
id: ca8b77a9-d499-4095-b793-5d5f330d450e
status: experimental
description: Detects PowerShell calling a credential prompt
references:
    - https://twitter.com/JohnLaTwC/status/850381440629981184
    - https://t.co/ezOTGy1a1G
tags:
    - attack.credential_access
    - attack.execution
    - attack.t1059.001
    - attack.t1086  # an old one
author: John Lambert (idea), Florian Roth (rule)
date: 2017/04/09
logsource:
    product: windows
    service: powershell
    definition: 'Script block logging must be enabled'
detection:
    selection:
        EventID: 4104
    keyword:
        Message:
            - '*PromptForCredential*'
    condition: all of them
falsepositives:
    - Unknown
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {($_.ID -eq "4104" -and ($_.message -match ".*PromptForCredential.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_id:"4104" AND Message.keyword:(*PromptForCredential*))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/ca8b77a9-d499-4095-b793-5d5f330d450e <<EOF
{
  "metadata": {
    "title": "PowerShell Credential Prompt",
    "description": "Detects PowerShell calling a credential prompt",
    "tags": [
      "attack.credential_access",
      "attack.execution",
      "attack.t1059.001",
      "attack.t1086"
    ],
    "query": "(winlog.event_id:\"4104\" AND Message.keyword:(*PromptForCredential*))"
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
                    "query": "(winlog.event_id:\"4104\" AND Message.keyword:(*PromptForCredential*))",
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
        "subject": "Sigma Rule 'PowerShell Credential Prompt'",
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
(EventID:"4104" AND Message.keyword:(*PromptForCredential*))
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="4104" (Message="*PromptForCredential*"))
```


### logpoint
    
```
(event_id="4104" Message IN ["*PromptForCredential*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*4104)(?=.*(?:.*.*PromptForCredential.*)))'
```



