| Title                    | DPAPI Domain Master Key Backup Attempt       |
|:-------------------------|:------------------|
| **Description**          | Detects anyone attempting a backup for the DPAPI Master Key. This events gets generated at the source and not the Domain Controller. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1003: OS Credential Dumping](https://attack.mitre.org/techniques/T1003)</li><li>[T1003.004: LSA Secrets](https://attack.mitre.org/techniques/T1003/004)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              | <ul><li>[T1003: OS Credential Dumping](../Triggers/T1003.md)</li><li>[T1003.004: LSA Secrets](../Triggers/T1003.004.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/06_credential_access/T1003_credential_dumping/domain_dpapi_backupkey_extraction.md](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/06_credential_access/T1003_credential_dumping/domain_dpapi_backupkey_extraction.md)</li></ul>  |
| **Author**               | Roberto Rodriguez @Cyb3rWard0g |


## Detection Rules

### Sigma rule

```
title: DPAPI Domain Master Key Backup Attempt
id: 39a94fd1-8c9a-4ff6-bf22-c058762f8014
description: Detects anyone attempting a backup for the DPAPI Master Key. This events gets generated at the source and not the Domain Controller.
status: experimental
date: 2019/08/10
author: Roberto Rodriguez @Cyb3rWard0g
references:
    - https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/06_credential_access/T1003_credential_dumping/domain_dpapi_backupkey_extraction.md
tags:
    - attack.credential_access
    - attack.t1003          # an old one
    - attack.t1003.004
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4692
    condition: selection
fields:
    - ComputerName
    - SubjectDomainName
    - SubjectUserName
falsepositives:
    - Unknown
level: critical

```





### powershell
    
```
Get-WinEvent -LogName Security | where {($_.ID -eq "4692") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND winlog.event_id:"4692")
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/39a94fd1-8c9a-4ff6-bf22-c058762f8014 <<EOF
{
  "metadata": {
    "title": "DPAPI Domain Master Key Backup Attempt",
    "description": "Detects anyone attempting a backup for the DPAPI Master Key. This events gets generated at the source and not the Domain Controller.",
    "tags": [
      "attack.credential_access",
      "attack.t1003",
      "attack.t1003.004"
    ],
    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"4692\")"
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
                    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"4692\")",
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
        "subject": "Sigma Rule 'DPAPI Domain Master Key Backup Attempt'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\n     ComputerName = {{_source.ComputerName}}\nSubjectDomainName = {{_source.SubjectDomainName}}\n  SubjectUserName = {{_source.SubjectUserName}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
EventID:"4692"
```


### splunk
    
```
(source="WinEventLog:Security" EventCode="4692") | table ComputerName,SubjectDomainName,SubjectUserName
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="4692")
```


### grep
    
```
grep -P '^4692'
```



