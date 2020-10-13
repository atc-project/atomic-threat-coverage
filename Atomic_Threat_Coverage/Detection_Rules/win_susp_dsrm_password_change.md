| Title                    | Password Change on Directory Service Restore Mode (DSRM) Account       |
|:-------------------------|:------------------|
| **Description**          | The Directory Service Restore Mode (DSRM) account is a local administrator account on Domain Controllers. Attackers may change the password to gain persistence. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1098: Account Manipulation](https://attack.mitre.org/techniques/T1098)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0028_4794_directory_services_restore_mode_admin_password_set](../Data_Needed/DN_0028_4794_directory_services_restore_mode_admin_password_set.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1098: Account Manipulation](../Triggers/T1098.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Initial installation of a domain controller</li></ul>  |
| **Development Status**   | stable |
| **References**           | <ul><li>[https://adsecurity.org/?p=1714](https://adsecurity.org/?p=1714)</li></ul>  |
| **Author**               | Thomas Patzke |


## Detection Rules

### Sigma rule

```
title: Password Change on Directory Service Restore Mode (DSRM) Account
id: 53ad8e36-f573-46bf-97e4-15ba5bf4bb51
status: stable
description: The Directory Service Restore Mode (DSRM) account is a local administrator account on Domain Controllers. Attackers may change the password to gain persistence.
references:
    - https://adsecurity.org/?p=1714
author: Thomas Patzke
date: 2017/02/19
modified: 2020/08/23
tags:
    - attack.persistence
    - attack.t1098
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4794
    condition: selection
falsepositives:
    - Initial installation of a domain controller
level: high

```





### powershell
    
```
Get-WinEvent -LogName Security | where {($_.ID -eq "4794") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND winlog.event_id:"4794")
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/53ad8e36-f573-46bf-97e4-15ba5bf4bb51 <<EOF
{
  "metadata": {
    "title": "Password Change on Directory Service Restore Mode (DSRM) Account",
    "description": "The Directory Service Restore Mode (DSRM) account is a local administrator account on Domain Controllers. Attackers may change the password to gain persistence.",
    "tags": [
      "attack.persistence",
      "attack.t1098"
    ],
    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"4794\")"
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
                    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"4794\")",
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
        "subject": "Sigma Rule 'Password Change on Directory Service Restore Mode (DSRM) Account'",
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
EventID:"4794"
```


### splunk
    
```
(source="WinEventLog:Security" EventCode="4794")
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="4794")
```


### grep
    
```
grep -P '^4794'
```



