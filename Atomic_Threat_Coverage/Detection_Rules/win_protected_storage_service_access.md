| Title                    | Protected Storage Service Access       |
|:-------------------------|:------------------|
| **Description**          | Detects access to a protected_storage service over the network. Potential abuse of DPAPI to extract domain backup keys from Domain Controllers |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1021: Remote Services](https://attack.mitre.org/techniques/T1021)</li><li>[T1021.002: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0032_5145_network_share_object_was_accessed_detailed](../Data_Needed/DN_0032_5145_network_share_object_was_accessed_detailed.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1021.002: SMB/Windows Admin Shares](../Triggers/T1021.002.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/06_credential_access/T1003_credential_dumping/domain_dpapi_backupkey_extraction.md](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/06_credential_access/T1003_credential_dumping/domain_dpapi_backupkey_extraction.md)</li></ul>  |
| **Author**               | Roberto Rodriguez @Cyb3rWard0g |


## Detection Rules

### Sigma rule

```
title: Protected Storage Service Access
id: 45545954-4016-43c6-855e-eae8f1c369dc
description: Detects access to a protected_storage service over the network. Potential abuse of DPAPI to extract domain backup keys from Domain Controllers
status: experimental
date: 2019/08/10
modified: 2020/08/23
author: Roberto Rodriguez @Cyb3rWard0g
references:
    - https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/06_credential_access/T1003_credential_dumping/domain_dpapi_backupkey_extraction.md
tags:
    - attack.lateral_movement
    - attack.t1021          # an old one
    - attack.t1021.002
logsource:
    product: windows
    service: security
detection:
    selection: 
        EventID: 5145
        ShareName|contains: 'IPC'
        RelativeTargetName: "protected_storage"
    condition: selection
falsepositives:
    - Unknown
level: critical
```





### powershell
    
```
Get-WinEvent -LogName Security | where {($_.ID -eq "5145" -and $_.message -match "ShareName.*.*IPC.*" -and $_.message -match "RelativeTargetName.*protected_storage") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND winlog.event_id:"5145" AND winlog.event_data.ShareName.keyword:*IPC* AND RelativeTargetName:"protected_storage")
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/45545954-4016-43c6-855e-eae8f1c369dc <<EOF
{
  "metadata": {
    "title": "Protected Storage Service Access",
    "description": "Detects access to a protected_storage service over the network. Potential abuse of DPAPI to extract domain backup keys from Domain Controllers",
    "tags": [
      "attack.lateral_movement",
      "attack.t1021",
      "attack.t1021.002"
    ],
    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"5145\" AND winlog.event_data.ShareName.keyword:*IPC* AND RelativeTargetName:\"protected_storage\")"
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
                    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"5145\" AND winlog.event_data.ShareName.keyword:*IPC* AND RelativeTargetName:\"protected_storage\")",
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
        "subject": "Sigma Rule 'Protected Storage Service Access'",
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
(EventID:"5145" AND ShareName.keyword:*IPC* AND RelativeTargetName:"protected_storage")
```


### splunk
    
```
(source="WinEventLog:Security" EventCode="5145" ShareName="*IPC*" RelativeTargetName="protected_storage")
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="5145" ShareName="*IPC*" RelativeTargetName="protected_storage")
```


### grep
    
```
grep -P '^(?:.*(?=.*5145)(?=.*.*IPC.*)(?=.*protected_storage))'
```



