| Title                    | RottenPotato Like Attack Pattern       |
|:-------------------------|:------------------|
| **Description**          | Detects logon events that have characteristics of events generated during an attack with RottenPotato and the like |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1171: LLMNR/NBT-NS Poisoning and Relay](https://attack.mitre.org/techniques/T1171)</li><li>[T1557.001: LLMNR/NBT-NS Poisoning and SMB Relay](https://attack.mitre.org/techniques/T1557/001)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0004_4624_windows_account_logon](../Data_Needed/DN_0004_4624_windows_account_logon.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://twitter.com/SBousseaden/status/1195284233729777665](https://twitter.com/SBousseaden/status/1195284233729777665)</li></ul>  |
| **Author**               | @SBousseaden, Florian Roth |


## Detection Rules

### Sigma rule

```
title: RottenPotato Like Attack Pattern
id: 16f5d8ca-44bd-47c8-acbe-6fc95a16c12f
status: experimental
description: Detects logon events that have characteristics of events generated during an attack with RottenPotato and the like
references:
    - https://twitter.com/SBousseaden/status/1195284233729777665
author: "@SBousseaden, Florian Roth"
date: 2019/11/15
tags:
    - attack.privilege_escalation
    - attack.credential_access
    - attack.t1171          # an old one
    - attack.t1557.001
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 3
        TargetUserName: 'ANONYMOUS_LOGON'
        WorkstationName: '-'
        SourceNetworkAddress: '127.0.0.1'
    condition: selection
falsepositives:
    - Unknown
level: high

```





### powershell
    
```
Get-WinEvent -LogName Security | where {($_.ID -eq "4624" -and $_.message -match "LogonType.*3" -and $_.message -match "TargetUserName.*ANONYMOUS_LOGON" -and $_.message -match "WorkstationName.*-" -and $_.message -match "SourceNetworkAddress.*127.0.0.1") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND winlog.event_id:"4624" AND winlog.event_data.LogonType:"3" AND TargetUserName:"ANONYMOUS_LOGON" AND winlog.event_data.WorkstationName:"\-" AND SourceNetworkAddress:"127.0.0.1")
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/16f5d8ca-44bd-47c8-acbe-6fc95a16c12f <<EOF
{
  "metadata": {
    "title": "RottenPotato Like Attack Pattern",
    "description": "Detects logon events that have characteristics of events generated during an attack with RottenPotato and the like",
    "tags": [
      "attack.privilege_escalation",
      "attack.credential_access",
      "attack.t1171",
      "attack.t1557.001"
    ],
    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"4624\" AND winlog.event_data.LogonType:\"3\" AND TargetUserName:\"ANONYMOUS_LOGON\" AND winlog.event_data.WorkstationName:\"\\-\" AND SourceNetworkAddress:\"127.0.0.1\")"
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
                    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"4624\" AND winlog.event_data.LogonType:\"3\" AND TargetUserName:\"ANONYMOUS_LOGON\" AND winlog.event_data.WorkstationName:\"\\-\" AND SourceNetworkAddress:\"127.0.0.1\")",
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
        "subject": "Sigma Rule 'RottenPotato Like Attack Pattern'",
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
(EventID:"4624" AND LogonType:"3" AND TargetUserName:"ANONYMOUS_LOGON" AND WorkstationName:"\-" AND SourceNetworkAddress:"127.0.0.1")
```


### splunk
    
```
(source="WinEventLog:Security" EventCode="4624" LogonType="3" TargetUserName="ANONYMOUS_LOGON" WorkstationName="-" SourceNetworkAddress="127.0.0.1")
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="4624" logon_type="3" TargetUserName="ANONYMOUS_LOGON" WorkstationName="-" SourceNetworkAddress="127.0.0.1")
```


### grep
    
```
grep -P '^(?:.*(?=.*4624)(?=.*3)(?=.*ANONYMOUS_LOGON)(?=.*-)(?=.*127\.0\.0\.1))'
```



