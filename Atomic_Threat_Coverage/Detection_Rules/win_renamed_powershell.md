| Title                    | Renamed PowerShell       |
|:-------------------------|:------------------|
| **Description**          | Detects the execution of a renamed PowerShell often used by attackers or malware |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1036: Masquerading](https://attack.mitre.org/techniques/T1036)</li><li>[T1036.003: Rename System Utilities](https://attack.mitre.org/techniques/T1036/003)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1036.003: Rename System Utilities](../Triggers/T1036.003.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://twitter.com/christophetd/status/1164506034720952320](https://twitter.com/christophetd/status/1164506034720952320)</li></ul>  |
| **Author**               | Florian Roth |
| Other Tags           | <ul><li>car.2013-05-009</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Renamed PowerShell
id: d178a2d7-129a-4ba4-8ee6-d6e1fecd5d20
status: experimental
description: Detects the execution of a renamed PowerShell often used by attackers or malware
references:
    - https://twitter.com/christophetd/status/1164506034720952320
author: Florian Roth
date: 2019/08/22
modified: 2020/09/06
tags:
    - car.2013-05-009
    - attack.defense_evasion
    - attack.t1036 # an old one
    - attack.t1036.003    
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Description: 'Windows PowerShell'
        Company: 'Microsoft Corporation'
    filter:
        Image: 
            - '*\powershell.exe'
            - '*\powershell_ise.exe'
    condition: selection and not filter
falsepositives:
    - Unknown
level: critical

```





### powershell
    
```
Get-WinEvent | where {(($_.message -match "Description.*Windows PowerShell" -and $_.message -match "Company.*Microsoft Corporation") -and  -not (($_.message -match "Image.*.*\\powershell.exe" -or $_.message -match "Image.*.*\\powershell_ise.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
((winlog.event_data.Description:"Windows\ PowerShell" AND Company:"Microsoft\ Corporation") AND (NOT (winlog.event_data.Image.keyword:(*\\powershell.exe OR *\\powershell_ise.exe))))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/d178a2d7-129a-4ba4-8ee6-d6e1fecd5d20 <<EOF
{
  "metadata": {
    "title": "Renamed PowerShell",
    "description": "Detects the execution of a renamed PowerShell often used by attackers or malware",
    "tags": [
      "car.2013-05-009",
      "attack.defense_evasion",
      "attack.t1036",
      "attack.t1036.003"
    ],
    "query": "((winlog.event_data.Description:\"Windows\\ PowerShell\" AND Company:\"Microsoft\\ Corporation\") AND (NOT (winlog.event_data.Image.keyword:(*\\\\powershell.exe OR *\\\\powershell_ise.exe))))"
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
                    "query": "((winlog.event_data.Description:\"Windows\\ PowerShell\" AND Company:\"Microsoft\\ Corporation\") AND (NOT (winlog.event_data.Image.keyword:(*\\\\powershell.exe OR *\\\\powershell_ise.exe))))",
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
        "subject": "Sigma Rule 'Renamed PowerShell'",
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
((Description:"Windows PowerShell" AND Company:"Microsoft Corporation") AND (NOT (Image.keyword:(*\\powershell.exe *\\powershell_ise.exe))))
```


### splunk
    
```
((Description="Windows PowerShell" Company="Microsoft Corporation") NOT ((Image="*\\powershell.exe" OR Image="*\\powershell_ise.exe")))
```


### logpoint
    
```
((Description="Windows PowerShell" Company="Microsoft Corporation")  -(Image IN ["*\\powershell.exe", "*\\powershell_ise.exe"]))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*Windows PowerShell)(?=.*Microsoft Corporation)))(?=.*(?!.*(?:.*(?=.*(?:.*.*\powershell\.exe|.*.*\powershell_ise\.exe))))))'
```



