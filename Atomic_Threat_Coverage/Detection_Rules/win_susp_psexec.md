| Title                    | Suspicious PsExec Execution       |
|:-------------------------|:------------------|
| **Description**          | detects execution of psexec or paexec with renamed service name, this rule helps to filter out the noise if psexec is used for legit purposes or if attacker uses a different psexec client other than sysinternal one |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1077: Windows Admin Shares](https://attack.mitre.org/techniques/T1077)</li><li>[T1021.002: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0032_5145_network_share_object_was_accessed_detailed](../Data_Needed/DN_0032_5145_network_share_object_was_accessed_detailed.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1021.002: SMB/Windows Admin Shares](../Triggers/T1021.002.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>nothing observed so far</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://blog.menasec.net/2019/02/threat-hunting-3-detecting-psexec.html](https://blog.menasec.net/2019/02/threat-hunting-3-detecting-psexec.html)</li></ul>  |
| **Author**               | Samir Bousseaden |


## Detection Rules

### Sigma rule

```
title: Suspicious PsExec Execution
id: c462f537-a1e3-41a6-b5fc-b2c2cef9bf82
description: detects execution of psexec or paexec with renamed service name, this rule helps to filter out the noise if psexec is used for legit purposes or if attacker uses a different psexec client other than sysinternal one
author: Samir Bousseaden
date: 2019/04/03
references:
    - https://blog.menasec.net/2019/02/threat-hunting-3-detecting-psexec.html
tags:
    - attack.lateral_movement
    - attack.t1077           # an old one
    - attack.t1021.002
logsource:
    product: windows
    service: security
    definition: 'The advanced audit policy setting "Object Access > Audit Detailed File Share" must be configured for Success/Failure'
detection:
    selection1:
        EventID: 5145
        ShareName: \\*\IPC$
        RelativeTargetName:
            - '*-stdin'
            - '*-stdout'
            - '*-stderr'
    selection2:
        EventID: 5145
        ShareName: \\*\IPC$
        RelativeTargetName: 'PSEXESVC*'
    condition: selection1 and not selection2
falsepositives:
    - nothing observed so far
level: high

```





### powershell
    
```
Get-WinEvent -LogName Security | where {(($_.ID -eq "5145" -and $_.message -match "ShareName.*\\.*\\IPC$" -and ($_.message -match "RelativeTargetName.*.*-stdin" -or $_.message -match "RelativeTargetName.*.*-stdout" -or $_.message -match "RelativeTargetName.*.*-stderr")) -and  -not ($_.ID -eq "5145" -and $_.message -match "ShareName.*\\.*\\IPC$" -and $_.message -match "RelativeTargetName.*PSEXESVC.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND (winlog.event_id:"5145" AND winlog.event_data.ShareName.keyword:\\*\\IPC$ AND RelativeTargetName.keyword:(*\-stdin OR *\-stdout OR *\-stderr)) AND (NOT (winlog.event_id:"5145" AND winlog.event_data.ShareName.keyword:\\*\\IPC$ AND RelativeTargetName.keyword:PSEXESVC*)))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/c462f537-a1e3-41a6-b5fc-b2c2cef9bf82 <<EOF
{
  "metadata": {
    "title": "Suspicious PsExec Execution",
    "description": "detects execution of psexec or paexec with renamed service name, this rule helps to filter out the noise if psexec is used for legit purposes or if attacker uses a different psexec client other than sysinternal one",
    "tags": [
      "attack.lateral_movement",
      "attack.t1077",
      "attack.t1021.002"
    ],
    "query": "(winlog.channel:\"Security\" AND (winlog.event_id:\"5145\" AND winlog.event_data.ShareName.keyword:\\\\*\\\\IPC$ AND RelativeTargetName.keyword:(*\\-stdin OR *\\-stdout OR *\\-stderr)) AND (NOT (winlog.event_id:\"5145\" AND winlog.event_data.ShareName.keyword:\\\\*\\\\IPC$ AND RelativeTargetName.keyword:PSEXESVC*)))"
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
                    "query": "(winlog.channel:\"Security\" AND (winlog.event_id:\"5145\" AND winlog.event_data.ShareName.keyword:\\\\*\\\\IPC$ AND RelativeTargetName.keyword:(*\\-stdin OR *\\-stdout OR *\\-stderr)) AND (NOT (winlog.event_id:\"5145\" AND winlog.event_data.ShareName.keyword:\\\\*\\\\IPC$ AND RelativeTargetName.keyword:PSEXESVC*)))",
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
        "subject": "Sigma Rule 'Suspicious PsExec Execution'",
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
((EventID:"5145" AND ShareName.keyword:\\*\\IPC$ AND RelativeTargetName.keyword:(*\-stdin *\-stdout *\-stderr)) AND (NOT (EventID:"5145" AND ShareName.keyword:\\*\\IPC$ AND RelativeTargetName.keyword:PSEXESVC*)))
```


### splunk
    
```
(source="WinEventLog:Security" (EventCode="5145" ShareName="\\*\\IPC$" (RelativeTargetName="*-stdin" OR RelativeTargetName="*-stdout" OR RelativeTargetName="*-stderr")) NOT (EventCode="5145" ShareName="\\*\\IPC$" RelativeTargetName="PSEXESVC*"))
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" (event_id="5145" ShareName="\\*\\IPC$" RelativeTargetName IN ["*-stdin", "*-stdout", "*-stderr"])  -(event_id="5145" ShareName="\\*\\IPC$" RelativeTargetName="PSEXESVC*"))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*5145)(?=.*\\.*\IPC\$)(?=.*(?:.*.*-stdin|.*.*-stdout|.*.*-stderr))))(?=.*(?!.*(?:.*(?=.*5145)(?=.*\\.*\IPC\$)(?=.*PSEXESVC.*)))))'
```



