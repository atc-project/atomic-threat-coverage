| Title                    | Possible SPN Enumeration       |
|:-------------------------|:------------------|
| **Description**          | Detects Service Principal Name Enumeration used for Kerberoasting |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1558.003: Kerberoasting](https://attack.mitre.org/techniques/T1558/003)</li><li>[T1208: Kerberoasting](https://attack.mitre.org/techniques/T1208)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1558.003: Kerberoasting](../Triggers/T1558.003.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Administrator Activity</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://p16.praetorian.com/blog/how-to-use-kerberoasting-t1208-for-privilege-escalation](https://p16.praetorian.com/blog/how-to-use-kerberoasting-t1208-for-privilege-escalation)</li></ul>  |
| **Author**               | Markus Neis, keepwatch |


## Detection Rules

### Sigma rule

```
title: Possible SPN Enumeration
id: 1eeed653-dbc8-4187-ad0c-eeebb20e6599
description: Detects Service Principal Name Enumeration used for Kerberoasting
status: experimental
references:
    - https://p16.praetorian.com/blog/how-to-use-kerberoasting-t1208-for-privilege-escalation
author: Markus Neis, keepwatch
date: 2018/11/14
tags:
    - attack.credential_access
    - attack.t1558.003
    - attack.t1208      # an old one
logsource:
    category: process_creation
    product: windows
detection:
    selection_image:
        Image: '*\setspn.exe'
    selection_desc:
        Description: '*Query or reset the computer* SPN attribute*'
    cmd:
        CommandLine: '*-q*'
    condition: (selection_image or selection_desc) and cmd
falsepositives:
    - Administrator Activity
level: medium

```





### powershell
    
```
Get-WinEvent | where {(($_.message -match "Image.*.*\\setspn.exe" -or $_.message -match "Description.*.*Query or reset the computer.* SPN attribute.*") -and $_.message -match "CommandLine.*.*-q.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
((winlog.event_data.Image.keyword:*\\setspn.exe OR winlog.event_data.Description.keyword:*Query\ or\ reset\ the\ computer*\ SPN\ attribute*) AND winlog.event_data.CommandLine.keyword:*\-q*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/1eeed653-dbc8-4187-ad0c-eeebb20e6599 <<EOF
{
  "metadata": {
    "title": "Possible SPN Enumeration",
    "description": "Detects Service Principal Name Enumeration used for Kerberoasting",
    "tags": [
      "attack.credential_access",
      "attack.t1558.003",
      "attack.t1208"
    ],
    "query": "((winlog.event_data.Image.keyword:*\\\\setspn.exe OR winlog.event_data.Description.keyword:*Query\\ or\\ reset\\ the\\ computer*\\ SPN\\ attribute*) AND winlog.event_data.CommandLine.keyword:*\\-q*)"
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
                    "query": "((winlog.event_data.Image.keyword:*\\\\setspn.exe OR winlog.event_data.Description.keyword:*Query\\ or\\ reset\\ the\\ computer*\\ SPN\\ attribute*) AND winlog.event_data.CommandLine.keyword:*\\-q*)",
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
        "subject": "Sigma Rule 'Possible SPN Enumeration'",
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
((Image.keyword:*\\setspn.exe OR Description.keyword:*Query or reset the computer* SPN attribute*) AND CommandLine.keyword:*\-q*)
```


### splunk
    
```
((Image="*\\setspn.exe" OR Description="*Query or reset the computer* SPN attribute*") CommandLine="*-q*")
```


### logpoint
    
```
((Image="*\\setspn.exe" OR Description="*Query or reset the computer* SPN attribute*") CommandLine="*-q*")
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?:.*.*\setspn\.exe|.*.*Query or reset the computer.* SPN attribute.*)))(?=.*.*-q.*))'
```



