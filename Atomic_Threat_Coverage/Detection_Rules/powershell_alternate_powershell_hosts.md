| Title                    | Alternate PowerShell Hosts       |
|:-------------------------|:------------------|
| **Description**          | Detects alternate PowerShell hosts potentially bypassing detections looking for powershell.exe |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Programs using PowerShell directly without invocation of a dedicated interpreter</li><li>MSP Detection Searcher</li><li>Citrix ConfigSync.ps1</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/02_execution/T1086_powershell/alternate_signed_powershell_hosts.md](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/02_execution/T1086_powershell/alternate_signed_powershell_hosts.md)</li></ul>  |
| **Author**               | Roberto Rodriguez @Cyb3rWard0g |
| Other Tags           | <ul><li>attack.t1059.001</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Alternate PowerShell Hosts
id: 64e8e417-c19a-475a-8d19-98ea705394cc
description: Detects alternate PowerShell hosts potentially bypassing detections looking for powershell.exe
status: experimental
date: 2019/08/11
modified: 2020/02/25
author: Roberto Rodriguez @Cyb3rWard0g
references:
    - https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/02_execution/T1086_powershell/alternate_signed_powershell_hosts.md
tags:
    - attack.execution
    - attack.t1086
    - attack.t1059.001
logsource:
    product: windows
    service: powershell
detection:
    selection:
        EventID:
            - 4103
            - 400
        ContextInfo: '*'
    filter:
        - ContextInfo: 'powershell.exe'
        - Message: 'powershell.exe'
        # Both fields contain key=value pairs where the key HostApplication ist relevant but
        # can't be referred directly as event field.
    condition: selection and not filter
falsepositives:
    - Programs using PowerShell directly without invocation of a dedicated interpreter
    - MSP Detection Searcher
    - Citrix ConfigSync.ps1
level: medium

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {((($_.ID -eq "4103" -or $_.ID -eq "400") -and $_.message -match "ContextInfo.*.*") -and  -not ($_.message -match "ContextInfo.*powershell.exe" -or $_.message -match "Message.*powershell.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
((winlog.event_id:("4103" OR "400") AND ContextInfo.keyword:*) AND (NOT (ContextInfo:"powershell.exe" OR Message:"powershell.exe")))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/64e8e417-c19a-475a-8d19-98ea705394cc <<EOF
{
  "metadata": {
    "title": "Alternate PowerShell Hosts",
    "description": "Detects alternate PowerShell hosts potentially bypassing detections looking for powershell.exe",
    "tags": [
      "attack.execution",
      "attack.t1086",
      "attack.t1059.001"
    ],
    "query": "((winlog.event_id:(\"4103\" OR \"400\") AND ContextInfo.keyword:*) AND (NOT (ContextInfo:\"powershell.exe\" OR Message:\"powershell.exe\")))"
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
                    "query": "((winlog.event_id:(\"4103\" OR \"400\") AND ContextInfo.keyword:*) AND (NOT (ContextInfo:\"powershell.exe\" OR Message:\"powershell.exe\")))",
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
        "subject": "Sigma Rule 'Alternate PowerShell Hosts'",
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
((EventID:("4103" "400") AND ContextInfo.keyword:*) AND (NOT (ContextInfo:"powershell.exe" OR Message:"powershell.exe")))
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-PowerShell/Operational" ((EventCode="4103" OR EventCode="400") ContextInfo="*") NOT (ContextInfo="powershell.exe" OR Message="powershell.exe"))
```


### logpoint
    
```
((event_id IN ["4103", "400"] ContextInfo="*")  -(ContextInfo="powershell.exe" OR Message="powershell.exe"))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*(?:.*4103|.*400))(?=.*.*)))(?=.*(?!.*(?:.*(?:.*(?=.*powershell\.exe)|.*(?=.*powershell\.exe))))))'
```



