| Title                    | Renamed PowerShell       |
|:-------------------------|:------------------|
| **Description**          | Detects the execution of a renamed PowerShell often used by attackers or malware |
| **ATT&amp;CK Tactic**    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| **ATT&amp;CK Technique** |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| **Data Needed**          | <ul><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
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
tags:
    - car.2013-05-009
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
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "Description.*Windows PowerShell" -and $_.message -match "Company.*Microsoft Corporation") -and  -not (($_.message -match "Image.*.*\\powershell.exe" -or $_.message -match "Image.*.*\\powershell_ise.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
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
      "car.2013-05-009"
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
(event_id="1" (Description="Windows PowerShell" Company="Microsoft Corporation")  -(Image IN ["*\\powershell.exe", "*\\powershell_ise.exe"]))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*Windows PowerShell)(?=.*Microsoft Corporation)))(?=.*(?!.*(?:.*(?=.*(?:.*.*\powershell\.exe|.*.*\powershell_ise\.exe))))))'
```



