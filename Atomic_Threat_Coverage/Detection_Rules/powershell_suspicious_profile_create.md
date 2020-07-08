| Title                    | Powershell Profile.ps1 Modification       |
|:-------------------------|:------------------|
| **Description**          | Detects a change in profile.ps1 of the Powershell profile |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| **ATT&amp;CK Technique** |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>System administrator create Powershell profile manually</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.welivesecurity.com/2019/05/29/turla-powershell-usage/](https://www.welivesecurity.com/2019/05/29/turla-powershell-usage/)</li></ul>  |
| **Author**               | HieuTT35 |


## Detection Rules

### Sigma rule

```
title: Powershell Profile.ps1 Modification
id: b5b78988-486d-4a80-b991-930eff3ff8bf
status: experimental
description: Detects a change in profile.ps1 of the Powershell profile
references:
    - https://www.welivesecurity.com/2019/05/29/turla-powershell-usage/
author: HieuTT35
date: 2019/10/24
modified: 2020/04/03
logsource:
    product: windows
    service: sysmon
detection:
    event:
        EventID: 11
    target1:
        TargetFilename|contains|all: 
            - '\My Documents\PowerShell\'
            - '\profile.ps1'
    target2:
        TargetFilename|contains|all: 
            - 'C:\Windows\System32\WindowsPowerShell\v1.0\'
            - '\profile.ps1'
    condition: event and (target1 or target2)
falsepositives:
    - System administrator create Powershell profile manually
level: high
tags:
    - attack.persistence
    - attack.privilege_escalation

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "11" -and $_.message -match "TargetFilename.*.*\\profile.ps1.*" -and ($_.message -match "TargetFilename.*.*\\My Documents\\PowerShell\\.*" -or $_.message -match "TargetFilename.*.*C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND winlog.event_id:"11" AND winlog.event_data.TargetFilename.keyword:*\\profile.ps1* AND (winlog.event_data.TargetFilename.keyword:*\\My\ Documents\\PowerShell\\* OR winlog.event_data.TargetFilename.keyword:*C\:\\Windows\\System32\\WindowsPowerShell\\v1.0\\*))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/b5b78988-486d-4a80-b991-930eff3ff8bf <<EOF
{
  "metadata": {
    "title": "Powershell Profile.ps1 Modification",
    "description": "Detects a change in profile.ps1 of the Powershell profile",
    "tags": [
      "attack.persistence",
      "attack.privilege_escalation"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"11\" AND winlog.event_data.TargetFilename.keyword:*\\\\profile.ps1* AND (winlog.event_data.TargetFilename.keyword:*\\\\My\\ Documents\\\\PowerShell\\\\* OR winlog.event_data.TargetFilename.keyword:*C\\:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\*))"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"11\" AND winlog.event_data.TargetFilename.keyword:*\\\\profile.ps1* AND (winlog.event_data.TargetFilename.keyword:*\\\\My\\ Documents\\\\PowerShell\\\\* OR winlog.event_data.TargetFilename.keyword:*C\\:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\*))",
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
        "subject": "Sigma Rule 'Powershell Profile.ps1 Modification'",
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
(EventID:"11" AND TargetFilename.keyword:*\\profile.ps1* AND (TargetFilename.keyword:*\\My Documents\\PowerShell\\* OR TargetFilename.keyword:*C\:\\Windows\\System32\\WindowsPowerShell\\v1.0\\*))
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="11" TargetFilename="*\\profile.ps1*" (TargetFilename="*\\My Documents\\PowerShell\\*" OR TargetFilename="*C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\*"))
```


### logpoint
    
```
(event_id="11" TargetFilename="*\\profile.ps1*" (TargetFilename="*\\My Documents\\PowerShell\\*" OR TargetFilename="*C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\*"))
```


### grep
    
```
grep -P '^(?:.*(?=.*11)(?=.*.*\profile\.ps1.*)(?=.*(?:.*(?:.*.*\My Documents\PowerShell\\.*|.*.*C:\Windows\System32\WindowsPowerShell\v1\.0\\.*))))'
```



