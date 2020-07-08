| Title                    | Active Directory Replication from Non Machine Account       |
|:-------------------------|:------------------|
| **Description**          | Detects potential abuse of Active Directory Replication Service (ADRS) from a non machine account to request credentials. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1003: OS Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              | <ul><li>[T1003: OS Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/06_credential_access/T1003_credential_dumping/ad_replication_non_machine_account.md](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/06_credential_access/T1003_credential_dumping/ad_replication_non_machine_account.md)</li></ul>  |
| **Author**               | Roberto Rodriguez @Cyb3rWard0g |


## Detection Rules

### Sigma rule

```
title: Active Directory Replication from Non Machine Account
id: 17d619c1-e020-4347-957e-1d1207455c93
description: Detects potential abuse of Active Directory Replication Service (ADRS) from a non machine account to request credentials.
status: experimental
date: 2019/07/26
modified: 2020/03/02
author: Roberto Rodriguez @Cyb3rWard0g
references:
    - https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/06_credential_access/T1003_credential_dumping/ad_replication_non_machine_account.md
tags:
    - attack.credential_access
    - attack.t1003
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4662
        AccessMask: '0x100'
        Properties|contains:
            - '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
            - '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
            - '89e95b76-444d-4c62-991a-0facbeda640c'
    filter:
        - SubjectUserName|endswith: '$'
        - SubjectUserName|startswith: 'MSOL_' #https://docs.microsoft.com/en-us/azure/active-directory/hybrid/reference-connect-accounts-permissions#ad-ds-connector-account
    condition: selection and not filter
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
Get-WinEvent -LogName Security | where {(($_.ID -eq "4662" -and $_.message -match "AccessMask.*0x100" -and ($_.message -match "Properties.*.*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2.*" -or $_.message -match "Properties.*.*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2.*" -or $_.message -match "Properties.*.*89e95b76-444d-4c62-991a-0facbeda640c.*")) -and  -not ($_.message -match "SubjectUserName.*.*$" -or $_.message -match "SubjectUserName.*MSOL_.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND (winlog.event_id:"4662" AND winlog.event_data.AccessMask:"0x100" AND winlog.event_data.Properties.keyword:(*1131f6aa\-9c07\-11d1\-f79f\-00c04fc2dcd2* OR *1131f6ad\-9c07\-11d1\-f79f\-00c04fc2dcd2* OR *89e95b76\-444d\-4c62\-991a\-0facbeda640c*)) AND (NOT (winlog.event_data.SubjectUserName.keyword:*$ OR winlog.event_data.SubjectUserName.keyword:MSOL_*)))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/17d619c1-e020-4347-957e-1d1207455c93 <<EOF
{
  "metadata": {
    "title": "Active Directory Replication from Non Machine Account",
    "description": "Detects potential abuse of Active Directory Replication Service (ADRS) from a non machine account to request credentials.",
    "tags": [
      "attack.credential_access",
      "attack.t1003"
    ],
    "query": "(winlog.channel:\"Security\" AND (winlog.event_id:\"4662\" AND winlog.event_data.AccessMask:\"0x100\" AND winlog.event_data.Properties.keyword:(*1131f6aa\\-9c07\\-11d1\\-f79f\\-00c04fc2dcd2* OR *1131f6ad\\-9c07\\-11d1\\-f79f\\-00c04fc2dcd2* OR *89e95b76\\-444d\\-4c62\\-991a\\-0facbeda640c*)) AND (NOT (winlog.event_data.SubjectUserName.keyword:*$ OR winlog.event_data.SubjectUserName.keyword:MSOL_*)))"
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
                    "query": "(winlog.channel:\"Security\" AND (winlog.event_id:\"4662\" AND winlog.event_data.AccessMask:\"0x100\" AND winlog.event_data.Properties.keyword:(*1131f6aa\\-9c07\\-11d1\\-f79f\\-00c04fc2dcd2* OR *1131f6ad\\-9c07\\-11d1\\-f79f\\-00c04fc2dcd2* OR *89e95b76\\-444d\\-4c62\\-991a\\-0facbeda640c*)) AND (NOT (winlog.event_data.SubjectUserName.keyword:*$ OR winlog.event_data.SubjectUserName.keyword:MSOL_*)))",
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
        "subject": "Sigma Rule 'Active Directory Replication from Non Machine Account'",
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
((EventID:"4662" AND AccessMask:"0x100" AND Properties.keyword:(*1131f6aa\-9c07\-11d1\-f79f\-00c04fc2dcd2* *1131f6ad\-9c07\-11d1\-f79f\-00c04fc2dcd2* *89e95b76\-444d\-4c62\-991a\-0facbeda640c*)) AND (NOT (SubjectUserName.keyword:*$ OR SubjectUserName.keyword:MSOL_*)))
```


### splunk
    
```
(source="WinEventLog:Security" (EventCode="4662" AccessMask="0x100" (Properties="*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*" OR Properties="*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*" OR Properties="*89e95b76-444d-4c62-991a-0facbeda640c*")) NOT (SubjectUserName="*$" OR SubjectUserName="MSOL_*")) | table ComputerName,SubjectDomainName,SubjectUserName
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" (event_id="4662" AccessMask="0x100" Properties IN ["*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*", "*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*", "*89e95b76-444d-4c62-991a-0facbeda640c*"])  -(SubjectUserName="*$" OR SubjectUserName="MSOL_*"))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*4662)(?=.*0x100)(?=.*(?:.*.*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2.*|.*.*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2.*|.*.*89e95b76-444d-4c62-991a-0facbeda640c.*))))(?=.*(?!.*(?:.*(?:.*(?=.*.*\$)|.*(?=.*MSOL_.*))))))'
```



