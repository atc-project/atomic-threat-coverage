| Title                    | SCM Database Handle Failure       |
|:-------------------------|:------------------|
| **Description**          | Detects non-system users failing to get a handle of the SCM database. |
| **ATT&amp;CK Tactic**    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| **ATT&amp;CK Technique** |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/07_discovery/T1000_local_admin_check/local_admin_remote_check_openscmanager.md](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/07_discovery/T1000_local_admin_check/local_admin_remote_check_openscmanager.md)</li></ul>  |
| **Author**               | Roberto Rodriguez @Cyb3rWard0g |


## Detection Rules

### Sigma rule

```
title: SCM Database Handle Failure
id: 13addce7-47b2-4ca0-a98f-1de964d1d669
description: Detects non-system users failing to get a handle of the SCM database.
status: experimental
date: 2019/08/12
author: Roberto Rodriguez @Cyb3rWard0g
references:
    - https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/07_discovery/T1000_local_admin_check/local_admin_remote_check_openscmanager.md
logsource:
    product: windows
    service: security
detection:
    selection: 
        EventID: 4656
        ObjectType: 'SC_MANAGER OBJECT'
        ObjectName: 'servicesactive'
        Keywords: "Audit Failure"
        SubjectLogonId: "0x3e4"
    condition: selection
falsepositives:
    - Unknown
level: critical

```





### powershell
    
```
Get-WinEvent -LogName Security | where {($_.ID -eq "4656" -and $_.message -match "ObjectType.*SC_MANAGER OBJECT" -and $_.message -match "ObjectName.*servicesactive" -and $_.message -match "Keywords.*Audit Failure" -and $_.message -match "SubjectLogonId.*0x3e4") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND winlog.event_id:"4656" AND winlog.event_data.ObjectType:"SC_MANAGER\ OBJECT" AND winlog.event_data.ObjectName:"servicesactive" AND Keywords:"Audit\ Failure" AND SubjectLogonId:"0x3e4")
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/13addce7-47b2-4ca0-a98f-1de964d1d669 <<EOF
{
  "metadata": {
    "title": "SCM Database Handle Failure",
    "description": "Detects non-system users failing to get a handle of the SCM database.",
    "tags": "",
    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"4656\" AND winlog.event_data.ObjectType:\"SC_MANAGER\\ OBJECT\" AND winlog.event_data.ObjectName:\"servicesactive\" AND Keywords:\"Audit\\ Failure\" AND SubjectLogonId:\"0x3e4\")"
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
                    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"4656\" AND winlog.event_data.ObjectType:\"SC_MANAGER\\ OBJECT\" AND winlog.event_data.ObjectName:\"servicesactive\" AND Keywords:\"Audit\\ Failure\" AND SubjectLogonId:\"0x3e4\")",
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
        "subject": "Sigma Rule 'SCM Database Handle Failure'",
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
(EventID:"4656" AND ObjectType:"SC_MANAGER OBJECT" AND ObjectName:"servicesactive" AND Keywords:"Audit Failure" AND SubjectLogonId:"0x3e4")
```


### splunk
    
```
(source="WinEventLog:Security" EventCode="4656" ObjectType="SC_MANAGER OBJECT" ObjectName="servicesactive" Keywords="Audit Failure" SubjectLogonId="0x3e4")
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="4656" ObjectType="SC_MANAGER OBJECT" ObjectName="servicesactive" Keywords="Audit Failure" SubjectLogonId="0x3e4")
```


### grep
    
```
grep -P '^(?:.*(?=.*4656)(?=.*SC_MANAGER OBJECT)(?=.*servicesactive)(?=.*Audit Failure)(?=.*0x3e4))'
```



