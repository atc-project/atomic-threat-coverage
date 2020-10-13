| Title                    | PSExec and WMI Process Creations Block       |
|:-------------------------|:------------------|
| **Description**          | Detects blocking of process creations originating from PSExec and WMI commands |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1047: Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047)</li><li>[T1035: Service Execution](https://attack.mitre.org/techniques/T1035)</li><li>[T1569.002: Service Execution](https://attack.mitre.org/techniques/T1569/002)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              | <ul><li>[T1047: Windows Management Instrumentation](../Triggers/T1047.md)</li><li>[T1569.002: Service Execution](../Triggers/T1569.002.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction?WT.mc_id=twitter#block-process-creations-originating-from-psexec-and-wmi-commands](https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction?WT.mc_id=twitter#block-process-creations-originating-from-psexec-and-wmi-commands)</li><li>[https://twitter.com/duff22b/status/1280166329660497920](https://twitter.com/duff22b/status/1280166329660497920)</li></ul>  |
| **Author**               | Bhabesh Raj |


## Detection Rules

### Sigma rule

```
title: PSExec and WMI Process Creations Block
id: 97b9ce1e-c5ab-11ea-87d0-0242ac130003
description: Detects blocking of process creations originating from PSExec and WMI commands
status: experimental
references:
    - https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction?WT.mc_id=twitter#block-process-creations-originating-from-psexec-and-wmi-commands
    - https://twitter.com/duff22b/status/1280166329660497920
author: Bhabesh Raj
date: 2020/07/14
tags:
    - attack.execution
    - attack.lateral_movement
    - attack.t1047
    - attack.t1035 # an old one
    - attack.t1569.002
logsource:
    product: windows_defender
    definition: 'Requirements:Enabled Block process creations originating from PSExec and WMI commands from Attack Surface Reduction (GUID: d1e49aac-8f56-4280-b9ba-993a6d77406c)'
detection:
    selection:
        EventID: 1121
        ProcessName|endswith:
          - '\wmiprvse.exe'
          - '\psexesvc.exe'
    condition: selection
falsepositives:
    - Unknown
level: high

```





### powershell
    
```
Get-WinEvent | where {($_.ID -eq "1121" -and ($_.message -match "ProcessName.*.*\\wmiprvse.exe" -or $_.message -match "ProcessName.*.*\\psexesvc.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_id:"1121" AND winlog.event_data.ProcessName.keyword:(*\\wmiprvse.exe OR *\\psexesvc.exe))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/97b9ce1e-c5ab-11ea-87d0-0242ac130003 <<EOF
{
  "metadata": {
    "title": "PSExec and WMI Process Creations Block",
    "description": "Detects blocking of process creations originating from PSExec and WMI commands",
    "tags": [
      "attack.execution",
      "attack.lateral_movement",
      "attack.t1047",
      "attack.t1035",
      "attack.t1569.002"
    ],
    "query": "(winlog.event_id:\"1121\" AND winlog.event_data.ProcessName.keyword:(*\\\\wmiprvse.exe OR *\\\\psexesvc.exe))"
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
                    "query": "(winlog.event_id:\"1121\" AND winlog.event_data.ProcessName.keyword:(*\\\\wmiprvse.exe OR *\\\\psexesvc.exe))",
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
        "subject": "Sigma Rule 'PSExec and WMI Process Creations Block'",
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
(EventID:"1121" AND ProcessName.keyword:(*\\wmiprvse.exe *\\psexesvc.exe))
```


### splunk
    
```
(EventCode="1121" (ProcessName="*\\wmiprvse.exe" OR ProcessName="*\\psexesvc.exe"))
```


### logpoint
    
```
(event_id="1121" ProcessName IN ["*\\wmiprvse.exe", "*\\psexesvc.exe"])
```


### grep
    
```
grep -P '^(?:.*(?=.*1121)(?=.*(?:.*.*\wmiprvse\.exe|.*.*\psexesvc\.exe)))'
```



