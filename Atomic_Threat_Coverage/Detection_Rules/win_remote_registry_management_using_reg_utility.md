| Title                    | Remote Registry Management Using Reg Utility       |
|:-------------------------|:------------------|
| **Description**          | Remote registry management using REG utility from non-admin workstation |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1112: Modify Registry](https://attack.mitre.org/techniques/T1112)</li><li>[T1012: Query Registry](https://attack.mitre.org/techniques/T1012)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              | <ul><li>[T1112: Modify Registry](../Triggers/T1112.md)</li><li>[T1012: Query Registry](../Triggers/T1012.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Legitimate usage of remote registry management by administrator</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment](https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment)</li></ul>  |
| **Author**               | Teymur Kheirkhabarov, oscd.community |
| Other Tags           | <ul><li>attack.s0075</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Remote Registry Management Using Reg Utility
id: 68fcba0d-73a5-475e-a915-e8b4c576827e
description: Remote registry management using REG utility from non-admin workstation
author: Teymur Kheirkhabarov, oscd.community
date: 2019/10/22
modified: 2019/11/13
references:
    - https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment
tags:
    - attack.defense_evasion
    - attack.discovery
    - attack.t1112
    - attack.t1012
    - attack.s0075
logsource:
    product: windows
    service: security
detection:
    selection_1:
        EventID: 5145
        RelativeTargetName|contains: '\winreg'
    selection_2:
        IpAddress: '%Admins_Workstations%'
    condition: selection_1 and not selection_2
falsepositives:
    - Legitimate usage of remote registry management by administrator
level: medium
status: experimental

```





### powershell
    
```
Get-WinEvent -LogName Security | where {(($_.ID -eq "5145" -and $_.message -match "RelativeTargetName.*.*\\winreg.*") -and  -not ($_.message -match "IpAddress.*%Admins_Workstations%")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND (winlog.event_id:"5145" AND RelativeTargetName.keyword:*\\winreg*) AND (NOT (winlog.event_data.IpAddress:"%Admins_Workstations%")))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/68fcba0d-73a5-475e-a915-e8b4c576827e <<EOF
{
  "metadata": {
    "title": "Remote Registry Management Using Reg Utility",
    "description": "Remote registry management using REG utility from non-admin workstation",
    "tags": [
      "attack.defense_evasion",
      "attack.discovery",
      "attack.t1112",
      "attack.t1012",
      "attack.s0075"
    ],
    "query": "(winlog.channel:\"Security\" AND (winlog.event_id:\"5145\" AND RelativeTargetName.keyword:*\\\\winreg*) AND (NOT (winlog.event_data.IpAddress:\"%Admins_Workstations%\")))"
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
                    "query": "(winlog.channel:\"Security\" AND (winlog.event_id:\"5145\" AND RelativeTargetName.keyword:*\\\\winreg*) AND (NOT (winlog.event_data.IpAddress:\"%Admins_Workstations%\")))",
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
        "subject": "Sigma Rule 'Remote Registry Management Using Reg Utility'",
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
((EventID:"5145" AND RelativeTargetName.keyword:*\\winreg*) AND (NOT (IpAddress:"%Admins_Workstations%")))
```


### splunk
    
```
(source="WinEventLog:Security" (EventCode="5145" RelativeTargetName="*\\winreg*") NOT (IpAddress="%Admins_Workstations%"))
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" (event_id="5145" RelativeTargetName="*\\winreg*")  -(IpAddress="%Admins_Workstations%"))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*5145)(?=.*.*\winreg.*)))(?=.*(?!.*(?:.*(?=.*%Admins_Workstations%)))))'
```



