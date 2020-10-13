| Title                    | Suspicious SYSVOL Domain Group Policy Access       |
|:-------------------------|:------------------|
| **Description**          | Detects Access to Domain Group Policies stored in SYSVOL |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1552.006: Group Policy Preferences](https://attack.mitre.org/techniques/T1552/006)</li><li>[T1003: OS Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1552.006: Group Policy Preferences](../Triggers/T1552.006.md)</li><li>[T1003: OS Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>administrative activity</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://adsecurity.org/?p=2288](https://adsecurity.org/?p=2288)</li><li>[https://www.hybrid-analysis.com/sample/f2943f5e45befa52fb12748ca7171d30096e1d4fc3c365561497c618341299d5?environmentId=100](https://www.hybrid-analysis.com/sample/f2943f5e45befa52fb12748ca7171d30096e1d4fc3c365561497c618341299d5?environmentId=100)</li></ul>  |
| **Author**               | Markus Neis |


## Detection Rules

### Sigma rule

```
title: Suspicious SYSVOL Domain Group Policy Access
id: 05f3c945-dcc8-4393-9f3d-af65077a8f86
status: experimental
description: Detects Access to Domain Group Policies stored in SYSVOL
references:
    - https://adsecurity.org/?p=2288
    - https://www.hybrid-analysis.com/sample/f2943f5e45befa52fb12748ca7171d30096e1d4fc3c365561497c618341299d5?environmentId=100
author: Markus Neis
date: 2018/04/09
modified: 2020/08/28
tags:
    - attack.credential_access
    - attack.t1552.006
    - attack.t1003      # an old one
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine: '*\SYSVOL\\*\policies\\*'
    condition: selection
falsepositives:
    - administrative activity
level: medium

```





### powershell
    
```
Get-WinEvent | where {$_.message -match "CommandLine.*.*\\SYSVOL\\.*\\policies\\.*" } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.CommandLine.keyword:*\\SYSVOL\\*\\policies\\*
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/05f3c945-dcc8-4393-9f3d-af65077a8f86 <<EOF
{
  "metadata": {
    "title": "Suspicious SYSVOL Domain Group Policy Access",
    "description": "Detects Access to Domain Group Policies stored in SYSVOL",
    "tags": [
      "attack.credential_access",
      "attack.t1552.006",
      "attack.t1003"
    ],
    "query": "winlog.event_data.CommandLine.keyword:*\\\\SYSVOL\\\\*\\\\policies\\\\*"
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
                    "query": "winlog.event_data.CommandLine.keyword:*\\\\SYSVOL\\\\*\\\\policies\\\\*",
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
        "subject": "Sigma Rule 'Suspicious SYSVOL Domain Group Policy Access'",
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
CommandLine.keyword:*\\SYSVOL\\*\\policies\\*
```


### splunk
    
```
CommandLine="*\\SYSVOL\\*\\policies\\*"
```


### logpoint
    
```
CommandLine="*\\SYSVOL\\*\\policies\\*"
```


### grep
    
```
grep -P '^.*\SYSVOL\\.*\policies\\.*'
```



