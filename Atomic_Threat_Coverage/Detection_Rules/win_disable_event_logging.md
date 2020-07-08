| Title                    | Disabling Windows Event Auditing       |
|:-------------------------|:------------------|
| **Description**          | Detects scenarios where system auditing (ie: windows event log auditing) is disabled. This may be used in a scenario where an entity would want to bypass local logging to evade detection when windows event logging is enabled and reviewed. Also, it is recommended to turn off "Local Group Policy Object Processing" via GPO, which will make sure that Active Directory GPOs take precedence over local/edited computer policies via something such as "gpedit.msc". Please note, that disabling "Local Group Policy Object Processing" may cause an issue in scenarios of one off specific GPO modifications -- however it is recommended to perform these modifications in Active Directory anyways. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1054: Indicator Blocking](https://attack.mitre.org/techniques/T1054)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://bit.ly/WinLogsZero2Hero](https://bit.ly/WinLogsZero2Hero)</li></ul>  |
| **Author**               | @neu5ron |
| Other Tags           | <ul><li>attack.t1562.006</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Disabling Windows Event Auditing
id: 69aeb277-f15f-4d2d-b32a-55e883609563
description: 'Detects scenarios where system auditing (ie: windows event log auditing) is disabled. This may be used in a scenario where an entity would want to bypass local logging to evade detection when windows event logging is enabled and reviewed. Also, it is recommended to turn off "Local Group Policy Object Processing" via GPO, which will make sure that Active Directory GPOs take precedence over local/edited computer policies via something such as "gpedit.msc". Please note, that disabling "Local Group Policy Object Processing" may cause an issue in scenarios of one off specific GPO modifications -- however it is recommended to perform these modifications in Active Directory anyways.'
references:
    - https://bit.ly/WinLogsZero2Hero
tags:
    - attack.defense_evasion
    - attack.t1054
    - attack.t1562.006
author: '@neu5ron'
date: 2017/11/19
logsource:
    product: windows
    service: security
    definition: 'Requirements: Audit Policy : Computer Management > Audit Policy Configuration, Group Policy : Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Policy Change\Audit Authorization Policy Change'
detection:
    selection:
        EventID: 4719
        AuditPolicyChanges: 'removed'
    condition: selection
falsepositives:
    - Unknown
level: high

```





### powershell
    
```
Get-WinEvent -LogName Security | where {($_.ID -eq "4719" -and $_.message -match "AuditPolicyChanges.*removed") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND winlog.event_id:"4719" AND winlog.event_data.AuditPolicyChanges:"removed")
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/69aeb277-f15f-4d2d-b32a-55e883609563 <<EOF
{
  "metadata": {
    "title": "Disabling Windows Event Auditing",
    "description": "Detects scenarios where system auditing (ie: windows event log auditing) is disabled. This may be used in a scenario where an entity would want to bypass local logging to evade detection when windows event logging is enabled and reviewed. Also, it is recommended to turn off \"Local Group Policy Object Processing\" via GPO, which will make sure that Active Directory GPOs take precedence over local/edited computer policies via something such as \"gpedit.msc\". Please note, that disabling \"Local Group Policy Object Processing\" may cause an issue in scenarios of one off specific GPO modifications -- however it is recommended to perform these modifications in Active Directory anyways.",
    "tags": [
      "attack.defense_evasion",
      "attack.t1054",
      "attack.t1562.006"
    ],
    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"4719\" AND winlog.event_data.AuditPolicyChanges:\"removed\")"
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
                    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"4719\" AND winlog.event_data.AuditPolicyChanges:\"removed\")",
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
        "subject": "Sigma Rule 'Disabling Windows Event Auditing'",
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
(EventID:"4719" AND AuditPolicyChanges:"removed")
```


### splunk
    
```
(source="WinEventLog:Security" EventCode="4719" AuditPolicyChanges="removed")
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="4719" AuditPolicyChanges="removed")
```


### grep
    
```
grep -P '^(?:.*(?=.*4719)(?=.*removed))'
```



