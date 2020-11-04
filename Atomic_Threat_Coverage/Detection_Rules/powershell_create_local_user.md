| Title                    | PowerShell Create Local User       |
|:-------------------------|:------------------|
| **Description**          | Detects creation of a local user via PowerShell |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li><li>[T1136: Create Account](https://attack.mitre.org/techniques/T1136)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0036_4104_windows_powershell_script_block](../Data_Needed/DN_0036_4104_windows_powershell_script_block.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li><li>[T1136: Create Account](../Triggers/T1136.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Legitimate user creation</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1136/T1136.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1136/T1136.md)</li></ul>  |
| **Author**               | @ROxPinTeddy |


## Detection Rules

### Sigma rule

```
title: PowerShell Create Local User
id: 243de76f-4725-4f2e-8225-a8a69b15ad61
status: experimental 
description: Detects creation of a local user via PowerShell
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1136/T1136.md
tags:
    - attack.execution
    - attack.t1086
    - attack.persistence
    - attack.t1136
author: '@ROxPinTeddy' 
date: 2020/04/11 
logsource:
    product: windows
    service: powershell
detection:
    selection:
        EventID: 4104
        Message|contains:
            - 'New-LocalUser'
    condition: selection 
falsepositives:
    - Legitimate user creation 
level: medium

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {($_.ID -eq "4104" -and ($_.message -match "Message.*.*New-LocalUser.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_id:"4104" AND winlog.event_data.Message.keyword:(*New\-LocalUser*))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/243de76f-4725-4f2e-8225-a8a69b15ad61 <<EOF
{
  "metadata": {
    "title": "PowerShell Create Local User",
    "description": "Detects creation of a local user via PowerShell",
    "tags": [
      "attack.execution",
      "attack.t1086",
      "attack.persistence",
      "attack.t1136"
    ],
    "query": "(winlog.event_id:\"4104\" AND winlog.event_data.Message.keyword:(*New\\-LocalUser*))"
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
                    "query": "(winlog.event_id:\"4104\" AND winlog.event_data.Message.keyword:(*New\\-LocalUser*))",
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
        "subject": "Sigma Rule 'PowerShell Create Local User'",
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
(EventID:"4104" AND Message.keyword:(*New\-LocalUser*))
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="4104" (Message="*New-LocalUser*"))
```


### logpoint
    
```
(event_id="4104" Message IN ["*New-LocalUser*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*4104)(?=.*(?:.*.*New-LocalUser.*)))'
```



