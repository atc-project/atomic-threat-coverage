| Title                    | Antivirus Web Shell Detection       |
|:-------------------------|:------------------|
| **Description**          | Detects a highly relevant Antivirus alert that reports a web shell |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1100: Web Shell](https://attack.mitre.org/techniques/T1100)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0084_av_alert](../Data_Needed/DN0084_av_alert.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Unlikely</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://www.nextron-systems.com/2018/09/08/antivirus-event-analysis-cheat-sheet-v1-4/](https://www.nextron-systems.com/2018/09/08/antivirus-event-analysis-cheat-sheet-v1-4/)</li></ul>  |
| **Author**               | Florian Roth |
| Other Tags           | <ul><li>attack.t1505.003</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Antivirus Web Shell Detection
id: fdf135a2-9241-4f96-a114-bb404948f736
description: Detects a highly relevant Antivirus alert that reports a web shell
date: 2018/09/09
modified: 2019/10/04
author: Florian Roth
references:
    - https://www.nextron-systems.com/2018/09/08/antivirus-event-analysis-cheat-sheet-v1-4/
tags:
    - attack.persistence
    - attack.t1100
    - attack.t1505.003
logsource:
    product: antivirus
detection:
    selection:
        Signature:
            - "PHP/Backdoor*"
            - "JSP/Backdoor*"
            - "ASP/Backdoor*"
            - "Backdoor.PHP*"
            - "Backdoor.JSP*"
            - "Backdoor.ASP*"
            - "*Webshell*"
    condition: selection
fields:
    - FileName
    - User
falsepositives:
    - Unlikely
level: critical

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "Signature.*PHP/Backdoor.*" -or $_.message -match "Signature.*JSP/Backdoor.*" -or $_.message -match "Signature.*ASP/Backdoor.*" -or $_.message -match "Signature.*Backdoor.PHP.*" -or $_.message -match "Signature.*Backdoor.JSP.*" -or $_.message -match "Signature.*Backdoor.ASP.*" -or $_.message -match "Signature.*.*Webshell.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.Signature.keyword:(PHP\/Backdoor* OR JSP\/Backdoor* OR ASP\/Backdoor* OR Backdoor.PHP* OR Backdoor.JSP* OR Backdoor.ASP* OR *Webshell*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/fdf135a2-9241-4f96-a114-bb404948f736 <<EOF
{
  "metadata": {
    "title": "Antivirus Web Shell Detection",
    "description": "Detects a highly relevant Antivirus alert that reports a web shell",
    "tags": [
      "attack.persistence",
      "attack.t1100",
      "attack.t1505.003"
    ],
    "query": "winlog.event_data.Signature.keyword:(PHP\\/Backdoor* OR JSP\\/Backdoor* OR ASP\\/Backdoor* OR Backdoor.PHP* OR Backdoor.JSP* OR Backdoor.ASP* OR *Webshell*)"
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
                    "query": "winlog.event_data.Signature.keyword:(PHP\\/Backdoor* OR JSP\\/Backdoor* OR ASP\\/Backdoor* OR Backdoor.PHP* OR Backdoor.JSP* OR Backdoor.ASP* OR *Webshell*)",
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
        "subject": "Sigma Rule 'Antivirus Web Shell Detection'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\nFileName = {{_source.FileName}}\n    User = {{_source.User}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
Signature.keyword:(PHP\/Backdoor* JSP\/Backdoor* ASP\/Backdoor* Backdoor.PHP* Backdoor.JSP* Backdoor.ASP* *Webshell*)
```


### splunk
    
```
(Signature="PHP/Backdoor*" OR Signature="JSP/Backdoor*" OR Signature="ASP/Backdoor*" OR Signature="Backdoor.PHP*" OR Signature="Backdoor.JSP*" OR Signature="Backdoor.ASP*" OR Signature="*Webshell*") | table FileName,User
```


### logpoint
    
```
Signature IN ["PHP/Backdoor*", "JSP/Backdoor*", "ASP/Backdoor*", "Backdoor.PHP*", "Backdoor.JSP*", "Backdoor.ASP*", "*Webshell*"]
```


### grep
    
```
grep -P '^(?:.*PHP/Backdoor.*|.*JSP/Backdoor.*|.*ASP/Backdoor.*|.*Backdoor\.PHP.*|.*Backdoor\.JSP.*|.*Backdoor\.ASP.*|.*.*Webshell.*)'
```



