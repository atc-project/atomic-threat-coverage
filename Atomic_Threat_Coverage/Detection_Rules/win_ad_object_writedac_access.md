| Title                    | AD Object WriteDAC Access       |
|:-------------------------|:------------------|
| **Description**          | Detects WRITE_DAC access to a domain object |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1222: File and Directory Permissions Modification](https://attack.mitre.org/techniques/T1222)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0030_4662_operation_was_performed_on_an_object](../Data_Needed/DN_0030_4662_operation_was_performed_on_an_object.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1222: File and Directory Permissions Modification](../Triggers/T1222.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/05_defense_evasion/T1222_file_permissions_modification/ad_replication_user_backdoor.md](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/05_defense_evasion/T1222_file_permissions_modification/ad_replication_user_backdoor.md)</li></ul>  |
| **Author**               | Roberto Rodriguez @Cyb3rWard0g |


## Detection Rules

### Sigma rule

```
title: AD Object WriteDAC Access
id: 028c7842-4243-41cd-be6f-12f3cf1a26c7
description: Detects WRITE_DAC access to a domain object
status: experimental
date: 2019/09/12
author: Roberto Rodriguez @Cyb3rWard0g
references:
    - https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/05_defense_evasion/T1222_file_permissions_modification/ad_replication_user_backdoor.md
tags:
    - attack.defense_evasion
    - attack.t1222
logsource:
    product: windows
    service: security
detection:
    selection: 
        EventID: 4662
        ObjectServer: 'DS'
        AccessMask: 0x40000
        ObjectType:
            - '19195a5b-6da0-11d0-afd3-00c04fd930c9'
            - 'domainDNS'
    condition: selection
falsepositives:
    - Unknown
level: critical

```





### powershell
    
```
Get-WinEvent -LogName Security | where {($_.ID -eq "4662" -and $_.message -match "ObjectServer.*DS" -and $_.message -match "AccessMask.*262144" -and ($_.message -match "19195a5b-6da0-11d0-afd3-00c04fd930c9" -or $_.message -match "domainDNS")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND winlog.event_id:"4662" AND ObjectServer:"DS" AND winlog.event_data.AccessMask:"262144" AND winlog.event_data.ObjectType:("19195a5b\-6da0\-11d0\-afd3\-00c04fd930c9" OR "domainDNS"))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/028c7842-4243-41cd-be6f-12f3cf1a26c7 <<EOF
{
  "metadata": {
    "title": "AD Object WriteDAC Access",
    "description": "Detects WRITE_DAC access to a domain object",
    "tags": [
      "attack.defense_evasion",
      "attack.t1222"
    ],
    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"4662\" AND ObjectServer:\"DS\" AND winlog.event_data.AccessMask:\"262144\" AND winlog.event_data.ObjectType:(\"19195a5b\\-6da0\\-11d0\\-afd3\\-00c04fd930c9\" OR \"domainDNS\"))"
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
                    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"4662\" AND ObjectServer:\"DS\" AND winlog.event_data.AccessMask:\"262144\" AND winlog.event_data.ObjectType:(\"19195a5b\\-6da0\\-11d0\\-afd3\\-00c04fd930c9\" OR \"domainDNS\"))",
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
        "subject": "Sigma Rule 'AD Object WriteDAC Access'",
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
(EventID:"4662" AND ObjectServer:"DS" AND AccessMask:"262144" AND ObjectType:("19195a5b\-6da0\-11d0\-afd3\-00c04fd930c9" "domainDNS"))
```


### splunk
    
```
(source="WinEventLog:Security" EventCode="4662" ObjectServer="DS" AccessMask="262144" (ObjectType="19195a5b-6da0-11d0-afd3-00c04fd930c9" OR ObjectType="domainDNS"))
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="4662" ObjectServer="DS" AccessMask="262144" ObjectType IN ["19195a5b-6da0-11d0-afd3-00c04fd930c9", "domainDNS"])
```


### grep
    
```
grep -P '^(?:.*(?=.*4662)(?=.*DS)(?=.*262144)(?=.*(?:.*19195a5b-6da0-11d0-afd3-00c04fd930c9|.*domainDNS)))'
```



