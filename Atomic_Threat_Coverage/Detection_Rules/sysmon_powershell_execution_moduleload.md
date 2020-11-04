| Title                    | PowerShell Execution       |
|:-------------------------|:------------------|
| **Description**          | Detects execution of PowerShell |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0011_7_windows_sysmon_image_loaded](../Data_Needed/DN_0011_7_windows_sysmon_image_loaded.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/hunters-forge/ThreatHunter-Playbook/blob/8869b7a58dba1cff63bae1d7ab923974b8c0539b/playbooks/WIN-190410151110.yaml](https://github.com/hunters-forge/ThreatHunter-Playbook/blob/8869b7a58dba1cff63bae1d7ab923974b8c0539b/playbooks/WIN-190410151110.yaml)</li></ul>  |
| **Author**               | Roberto Rodriguez @Cyb3rWard0g |


## Detection Rules

### Sigma rule

```
title: PowerShell Execution
id: 867613fb-fa60-4497-a017-a82df74a172c
description: Detects execution of PowerShell
status: experimental
date: 2019/09/12
modified: 2019/11/10
author: Roberto Rodriguez @Cyb3rWard0g
references:
    - https://github.com/hunters-forge/ThreatHunter-Playbook/blob/8869b7a58dba1cff63bae1d7ab923974b8c0539b/playbooks/WIN-190410151110.yaml
logsource:
    product: windows
    service: sysmon
tags:
    - attack.execution
    - attack.t1086
detection:
    selection: 
        EventID: 7
        Description: 'system.management.automation'
        ImageLoaded|contains: 'system.management.automation'
    condition: selection
fields:
    - ComputerName
    - Image
    - ProcessID
    - ImageLoaded
falsepositives:
    - Unknown
level: medium

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "7" -and $_.message -match "Description.*system.management.automation" -and $_.message -match "ImageLoaded.*.*system.management.automation.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND winlog.event_id:"7" AND winlog.event_data.Description:"system.management.automation" AND winlog.event_data.ImageLoaded.keyword:*system.management.automation*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/867613fb-fa60-4497-a017-a82df74a172c <<EOF
{
  "metadata": {
    "title": "PowerShell Execution",
    "description": "Detects execution of PowerShell",
    "tags": [
      "attack.execution",
      "attack.t1086"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"7\" AND winlog.event_data.Description:\"system.management.automation\" AND winlog.event_data.ImageLoaded.keyword:*system.management.automation*)"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"7\" AND winlog.event_data.Description:\"system.management.automation\" AND winlog.event_data.ImageLoaded.keyword:*system.management.automation*)",
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
        "subject": "Sigma Rule 'PowerShell Execution'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\nComputerName = {{_source.ComputerName}}\n       Image = {{_source.Image}}\n   ProcessID = {{_source.ProcessID}}\n ImageLoaded = {{_source.ImageLoaded}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
(EventID:"7" AND Description:"system.management.automation" AND ImageLoaded.keyword:*system.management.automation*)
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="7" Description="system.management.automation" ImageLoaded="*system.management.automation*") | table ComputerName,Image,ProcessID,ImageLoaded
```


### logpoint
    
```
(event_id="7" Description="system.management.automation" ImageLoaded="*system.management.automation*")
```


### grep
    
```
grep -P '^(?:.*(?=.*7)(?=.*system\.management\.automation)(?=.*.*system\.management\.automation.*))'
```



