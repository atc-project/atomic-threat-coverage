| Title                    | Possible Impacket SecretDump Remote Activity       |
|:-------------------------|:------------------|
| **Description**          | Detect AD credential dumping using impacket secretdump HKTL |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1003: OS Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              | <ul><li>[T1003: OS Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>pentesting</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://blog.menasec.net/2019/02/threat-huting-10-impacketsecretdump.html](https://blog.menasec.net/2019/02/threat-huting-10-impacketsecretdump.html)</li></ul>  |
| **Author**               | Samir Bousseaden |
| Other Tags           | <ul><li>attack.t1003.002</li><li>attack.t1003.004</li><li>attack.t1003.003</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Possible Impacket SecretDump Remote Activity
id: 252902e3-5830-4cf6-bf21-c22083dfd5cf
description: Detect AD credential dumping using impacket secretdump HKTL
author: Samir Bousseaden
date: 2019/04/03
references:
    - https://blog.menasec.net/2019/02/threat-huting-10-impacketsecretdump.html
tags:
    - attack.credential_access
    - attack.t1003
    - attack.t1003.002
    - attack.t1003.004
    - attack.t1003.003
logsource:
    product: windows
    service: security
    description: 'The advanced audit policy setting "Object Access > Audit Detailed File Share" must be configured for Success/Failure'
detection:
    selection:
        EventID: 5145
        ShareName: \\*\ADMIN$
        RelativeTargetName: 'SYSTEM32\\*.tmp'
    condition: selection
falsepositives:
    - pentesting
level: high

```





### powershell
    
```
Get-WinEvent -LogName Security | where {($_.ID -eq "5145" -and $_.message -match "ShareName.*\\.*\\ADMIN$" -and $_.message -match "RelativeTargetName.*SYSTEM32\\.*.tmp") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND winlog.event_id:"5145" AND winlog.event_data.ShareName.keyword:\\*\\ADMIN$ AND RelativeTargetName.keyword:SYSTEM32\\*.tmp)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/252902e3-5830-4cf6-bf21-c22083dfd5cf <<EOF
{
  "metadata": {
    "title": "Possible Impacket SecretDump Remote Activity",
    "description": "Detect AD credential dumping using impacket secretdump HKTL",
    "tags": [
      "attack.credential_access",
      "attack.t1003",
      "attack.t1003.002",
      "attack.t1003.004",
      "attack.t1003.003"
    ],
    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"5145\" AND winlog.event_data.ShareName.keyword:\\\\*\\\\ADMIN$ AND RelativeTargetName.keyword:SYSTEM32\\\\*.tmp)"
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
                    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"5145\" AND winlog.event_data.ShareName.keyword:\\\\*\\\\ADMIN$ AND RelativeTargetName.keyword:SYSTEM32\\\\*.tmp)",
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
        "subject": "Sigma Rule 'Possible Impacket SecretDump Remote Activity'",
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
(EventID:"5145" AND ShareName.keyword:\\*\\ADMIN$ AND RelativeTargetName.keyword:SYSTEM32\\*.tmp)
```


### splunk
    
```
(source="WinEventLog:Security" EventCode="5145" ShareName="\\*\\ADMIN$" RelativeTargetName="SYSTEM32\\*.tmp")
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="5145" ShareName="\\*\\ADMIN$" RelativeTargetName="SYSTEM32\\*.tmp")
```


### grep
    
```
grep -P '^(?:.*(?=.*5145)(?=.*\\.*\ADMIN\$)(?=.*SYSTEM32\\.*\.tmp))'
```



