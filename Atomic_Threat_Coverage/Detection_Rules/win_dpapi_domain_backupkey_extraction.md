| Title                    | DPAPI Domain Backup Key Extraction       |
|:-------------------------|:------------------|
| **Description**          | Detects tools extracting LSA secret DPAPI domain backup key from Domain Controllers |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1003: OS Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              | <ul><li>[T1003: OS Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/06_credential_access/T1003_credential_dumping/domain_dpapi_backupkey_extraction.md](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/06_credential_access/T1003_credential_dumping/domain_dpapi_backupkey_extraction.md)</li></ul>  |
| **Author**               | Roberto Rodriguez @Cyb3rWard0g |
| Other Tags           | <ul><li>attack.t1003.004</li></ul> | 

## Detection Rules

### Sigma rule

```
title: DPAPI Domain Backup Key Extraction
id: 4ac1f50b-3bd0-4968-902d-868b4647937e
description: Detects tools extracting LSA secret DPAPI domain backup key from Domain Controllers
status: experimental
date: 2019/06/20
author: Roberto Rodriguez @Cyb3rWard0g
references:
    - https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/06_credential_access/T1003_credential_dumping/domain_dpapi_backupkey_extraction.md
tags:
    - attack.credential_access
    - attack.t1003
    - attack.t1003.004
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4662
        ObjectType: 'SecretObject'
        AccessMask: '0x2'
        ObjectName: 'BCKUPKEY'
    condition: selection
falsepositives:
    - Unknown
level: critical

```





### powershell
    
```
Get-WinEvent -LogName Security | where {($_.ID -eq "4662" -and $_.message -match "ObjectType.*SecretObject" -and $_.message -match "AccessMask.*0x2" -and $_.message -match "ObjectName.*BCKUPKEY") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND winlog.event_id:"4662" AND winlog.event_data.ObjectType:"SecretObject" AND winlog.event_data.AccessMask:"0x2" AND winlog.event_data.ObjectName:"BCKUPKEY")
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/4ac1f50b-3bd0-4968-902d-868b4647937e <<EOF
{
  "metadata": {
    "title": "DPAPI Domain Backup Key Extraction",
    "description": "Detects tools extracting LSA secret DPAPI domain backup key from Domain Controllers",
    "tags": [
      "attack.credential_access",
      "attack.t1003",
      "attack.t1003.004"
    ],
    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"4662\" AND winlog.event_data.ObjectType:\"SecretObject\" AND winlog.event_data.AccessMask:\"0x2\" AND winlog.event_data.ObjectName:\"BCKUPKEY\")"
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
                    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"4662\" AND winlog.event_data.ObjectType:\"SecretObject\" AND winlog.event_data.AccessMask:\"0x2\" AND winlog.event_data.ObjectName:\"BCKUPKEY\")",
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
        "subject": "Sigma Rule 'DPAPI Domain Backup Key Extraction'",
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
(EventID:"4662" AND ObjectType:"SecretObject" AND AccessMask:"0x2" AND ObjectName:"BCKUPKEY")
```


### splunk
    
```
(source="WinEventLog:Security" EventCode="4662" ObjectType="SecretObject" AccessMask="0x2" ObjectName="BCKUPKEY")
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="4662" ObjectType="SecretObject" AccessMask="0x2" ObjectName="BCKUPKEY")
```


### grep
    
```
grep -P '^(?:.*(?=.*4662)(?=.*SecretObject)(?=.*0x2)(?=.*BCKUPKEY))'
```



