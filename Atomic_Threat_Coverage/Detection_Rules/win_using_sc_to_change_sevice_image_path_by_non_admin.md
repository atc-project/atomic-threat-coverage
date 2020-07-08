| Title                    | Possible Privilege Escalation via Weak Service Permissions       |
|:-------------------------|:------------------|
| **Description**          | Detection of sc.exe utility spawning by user with Medium integrity level to change service ImagePath or FailureCommand |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1134: Access Token Manipulation](https://attack.mitre.org/techniques/T1134)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment](https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment)</li><li>[https://pentestlab.blog/2017/03/30/weak-service-permissions/](https://pentestlab.blog/2017/03/30/weak-service-permissions/)</li></ul>  |
| **Author**               | Teymur Kheirkhabarov |


## Detection Rules

### Sigma rule

```
title: Possible Privilege Escalation via Weak Service Permissions
id: d937b75f-a665-4480-88a5-2f20e9f9b22a
description: Detection of sc.exe utility spawning by user with Medium integrity level to change service ImagePath or FailureCommand
references:
    - https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment
    - https://pentestlab.blog/2017/03/30/weak-service-permissions/
tags:
    - attack.privilege_escalation
    - attack.t1134
status: experimental
author: Teymur Kheirkhabarov
date: 2019/10/26
modified: 2019/11/11
logsource:
    category: process_creation
    product: windows
detection:
    scbynonadmin:
        Image|endswith: '\sc.exe'
        IntegrityLevel: 'Medium'
    binpath:
        CommandLine|contains|all:
            - 'config'
            - 'binPath'
    failurecommand:
        CommandLine|contains|all: 
            - 'failure'
            - 'command'
    condition: scbynonadmin and (binpath or failurecommand)
falsepositives:
    - Unknown
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\\sc.exe" -and $_.message -match "IntegrityLevel.*Medium" -and ($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*config.*" -and $_.message -match "CommandLine.*.*binPath.*") -or ($_.message -match "CommandLine.*.*failure.*" -and $_.message -match "CommandLine.*.*command.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
((winlog.event_data.Image.keyword:*\\sc.exe AND IntegrityLevel:"Medium") AND ((winlog.event_data.CommandLine.keyword:*config* AND winlog.event_data.CommandLine.keyword:*binPath*) OR (winlog.event_data.CommandLine.keyword:*failure* AND winlog.event_data.CommandLine.keyword:*command*)))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/d937b75f-a665-4480-88a5-2f20e9f9b22a <<EOF
{
  "metadata": {
    "title": "Possible Privilege Escalation via Weak Service Permissions",
    "description": "Detection of sc.exe utility spawning by user with Medium integrity level to change service ImagePath or FailureCommand",
    "tags": [
      "attack.privilege_escalation",
      "attack.t1134"
    ],
    "query": "((winlog.event_data.Image.keyword:*\\\\sc.exe AND IntegrityLevel:\"Medium\") AND ((winlog.event_data.CommandLine.keyword:*config* AND winlog.event_data.CommandLine.keyword:*binPath*) OR (winlog.event_data.CommandLine.keyword:*failure* AND winlog.event_data.CommandLine.keyword:*command*)))"
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
                    "query": "((winlog.event_data.Image.keyword:*\\\\sc.exe AND IntegrityLevel:\"Medium\") AND ((winlog.event_data.CommandLine.keyword:*config* AND winlog.event_data.CommandLine.keyword:*binPath*) OR (winlog.event_data.CommandLine.keyword:*failure* AND winlog.event_data.CommandLine.keyword:*command*)))",
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
        "subject": "Sigma Rule 'Possible Privilege Escalation via Weak Service Permissions'",
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
((Image.keyword:*\\sc.exe AND IntegrityLevel:"Medium") AND ((CommandLine.keyword:*config* AND CommandLine.keyword:*binPath*) OR (CommandLine.keyword:*failure* AND CommandLine.keyword:*command*)))
```


### splunk
    
```
((Image="*\\sc.exe" IntegrityLevel="Medium") ((CommandLine="*config*" CommandLine="*binPath*") OR (CommandLine="*failure*" CommandLine="*command*")))
```


### logpoint
    
```
(event_id="1" Image="*\\sc.exe" IntegrityLevel="Medium" ((CommandLine="*config*" CommandLine="*binPath*") OR (CommandLine="*failure*" CommandLine="*command*")))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*.*\sc\.exe)(?=.*Medium)))(?=.*(?:.*(?:.*(?:.*(?=.*.*config.*)(?=.*.*binPath.*))|.*(?:.*(?=.*.*failure.*)(?=.*.*command.*))))))'
```



