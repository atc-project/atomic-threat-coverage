| Title                    | Weak Encryption Enabled and Kerberoast       |
|:-------------------------|:------------------|
| **Description**          | Detects scenario where weak encryption is enabled for a user profile which could be used for hash/password cracking. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1089: Disabling Security Tools](https://attack.mitre.org/techniques/T1089)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0027_4738_user_account_was_changed](../Data_Needed/DN_0027_4738_user_account_was_changed.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1089: Disabling Security Tools](../Triggers/T1089.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://adsecurity.org/?p=2053](https://adsecurity.org/?p=2053)</li><li>[https://www.harmj0y.net/blog/activedirectory/roasting-as-reps/](https://www.harmj0y.net/blog/activedirectory/roasting-as-reps/)</li></ul>  |
| **Author**               | @neu5ron |


## Detection Rules

### Sigma rule

```
title: Weak Encryption Enabled and Kerberoast
id: f6de9536-0441-4b3f-a646-f4e00f300ffd
description: Detects scenario where weak encryption is enabled for a user profile which could be used for hash/password cracking.
references:
    - https://adsecurity.org/?p=2053
    - https://www.harmj0y.net/blog/activedirectory/roasting-as-reps/
author: '@neu5ron'
date: 2017/07/30
tags:
    - attack.defense_evasion
    - attack.t1089
logsource:
    product: windows
    service: security
    definition: 'Requirements: Audit Policy : Account Management > Audit User Account Management, Group Policy : Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Account Management\Audit User Account Management'
detection:
    selection:
        EventID: 4738
    keywords:
        Message:
        - '*DES*'
        - '*Preauth*'
        - '*Encrypted*'
    filters:
        Message:
            - '*Enabled*'
    condition: selection and keywords and filters
falsepositives:
    - Unknown
level: high

```





### powershell
    
```
Get-WinEvent -LogName Security | where {($_.ID -eq "4738" -and ($_.message -match "Message.*.*DES.*" -or $_.message -match "Message.*.*Preauth.*" -or $_.message -match "Message.*.*Encrypted.*") -and ($_.message -match "Message.*.*Enabled.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND winlog.event_id:"4738" AND winlog.event_data.Message.keyword:(*DES* OR *Preauth* OR *Encrypted*) AND winlog.event_data.Message.keyword:(*Enabled*))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/f6de9536-0441-4b3f-a646-f4e00f300ffd <<EOF
{
  "metadata": {
    "title": "Weak Encryption Enabled and Kerberoast",
    "description": "Detects scenario where weak encryption is enabled for a user profile which could be used for hash/password cracking.",
    "tags": [
      "attack.defense_evasion",
      "attack.t1089"
    ],
    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"4738\" AND winlog.event_data.Message.keyword:(*DES* OR *Preauth* OR *Encrypted*) AND winlog.event_data.Message.keyword:(*Enabled*))"
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
                    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"4738\" AND winlog.event_data.Message.keyword:(*DES* OR *Preauth* OR *Encrypted*) AND winlog.event_data.Message.keyword:(*Enabled*))",
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
      "email": {
        "to": "root@localhost",
        "subject": "Sigma Rule 'Weak Encryption Enabled and Kerberoast'",
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
(EventID:"4738" AND Message.keyword:(*DES* *Preauth* *Encrypted*) AND Message.keyword:(*Enabled*))
```


### splunk
    
```
(source="WinEventLog:Security" EventCode="4738" (Message="*DES*" OR Message="*Preauth*" OR Message="*Encrypted*") (Message="*Enabled*"))
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="4738" Message IN ["*DES*", "*Preauth*", "*Encrypted*"] Message IN ["*Enabled*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*4738)(?=.*(?:.*.*DES.*|.*.*Preauth.*|.*.*Encrypted.*))(?=.*(?:.*.*Enabled.*)))'
```



