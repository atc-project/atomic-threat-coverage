| Title                    | Successful Overpass the Hash Attempt       |
|:-------------------------|:------------------|
| **Description**          | Detects successful logon with logon type 9 (NewCredentials) which matches the Overpass the Hash behavior of e.g Mimikatz's sekurlsa::pth module. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1075: Pass the Hash](https://attack.mitre.org/techniques/T1075)</li><li>[T1550.002: Pass the Hash](https://attack.mitre.org/techniques/T1550/002)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0004_4624_windows_account_logon](../Data_Needed/DN_0004_4624_windows_account_logon.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1550.002: Pass the Hash](../Triggers/T1550.002.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Runas command-line tool using /netonly parameter</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://cyberwardog.blogspot.de/2017/04/chronicles-of-threat-hunter-hunting-for.html](https://cyberwardog.blogspot.de/2017/04/chronicles-of-threat-hunter-hunting-for.html)</li></ul>  |
| **Author**               | Roberto Rodriguez (source), Dominik Schaudel (rule) |
| Other Tags           | <ul><li>attack.s0002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Successful Overpass the Hash Attempt
id: 192a0330-c20b-4356-90b6-7b7049ae0b87
status: experimental
description: Detects successful logon with logon type 9 (NewCredentials) which matches the Overpass the Hash behavior of e.g Mimikatz's sekurlsa::pth module.
references:
    - https://cyberwardog.blogspot.de/2017/04/chronicles-of-threat-hunter-hunting-for.html
author: Roberto Rodriguez (source), Dominik Schaudel (rule)
date: 2018/02/12
tags:
    - attack.lateral_movement
    - attack.t1075          # an old one
    - attack.s0002
    - attack.t1550.002
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 9
        LogonProcessName: seclogo
        AuthenticationPackageName: Negotiate
    condition: selection
falsepositives:
    - Runas command-line tool using /netonly parameter
level: high

```





### powershell
    
```
Get-WinEvent -LogName Security | where {($_.ID -eq "4624" -and $_.message -match "LogonType.*9" -and $_.message -match "LogonProcessName.*seclogo" -and $_.message -match "AuthenticationPackageName.*Negotiate") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND winlog.event_id:"4624" AND winlog.event_data.LogonType:"9" AND winlog.event_data.LogonProcessName:"seclogo" AND winlog.event_data.AuthenticationPackageName:"Negotiate")
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/192a0330-c20b-4356-90b6-7b7049ae0b87 <<EOF
{
  "metadata": {
    "title": "Successful Overpass the Hash Attempt",
    "description": "Detects successful logon with logon type 9 (NewCredentials) which matches the Overpass the Hash behavior of e.g Mimikatz's sekurlsa::pth module.",
    "tags": [
      "attack.lateral_movement",
      "attack.t1075",
      "attack.s0002",
      "attack.t1550.002"
    ],
    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"4624\" AND winlog.event_data.LogonType:\"9\" AND winlog.event_data.LogonProcessName:\"seclogo\" AND winlog.event_data.AuthenticationPackageName:\"Negotiate\")"
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
                    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"4624\" AND winlog.event_data.LogonType:\"9\" AND winlog.event_data.LogonProcessName:\"seclogo\" AND winlog.event_data.AuthenticationPackageName:\"Negotiate\")",
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
        "subject": "Sigma Rule 'Successful Overpass the Hash Attempt'",
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
(EventID:"4624" AND LogonType:"9" AND LogonProcessName:"seclogo" AND AuthenticationPackageName:"Negotiate")
```


### splunk
    
```
(source="WinEventLog:Security" EventCode="4624" LogonType="9" LogonProcessName="seclogo" AuthenticationPackageName="Negotiate")
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="4624" logon_type="9" logon_process="seclogo" AuthenticationPackageName="Negotiate")
```


### grep
    
```
grep -P '^(?:.*(?=.*4624)(?=.*9)(?=.*seclogo)(?=.*Negotiate))'
```



