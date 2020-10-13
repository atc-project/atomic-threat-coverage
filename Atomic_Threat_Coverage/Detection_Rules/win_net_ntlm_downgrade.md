| Title                    | NetNTLM Downgrade Attack       |
|:-------------------------|:------------------|
| **Description**          | Detects NetNTLM downgrade attack |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1089: Disabling Security Tools](https://attack.mitre.org/techniques/T1089)</li><li>[T1562.001: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001)</li><li>[T1112: Modify Registry](https://attack.mitre.org/techniques/T1112)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li><li>[DN_0059_4657_registry_value_was_modified](../Data_Needed/DN_0059_4657_registry_value_was_modified.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1562.001: Disable or Modify Tools](../Triggers/T1562.001.md)</li><li>[T1112: Modify Registry](../Triggers/T1112.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://www.optiv.com/blog/post-exploitation-using-netntlm-downgrade-attacks](https://www.optiv.com/blog/post-exploitation-using-netntlm-downgrade-attacks)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
action: global
title: NetNTLM Downgrade Attack
id: d67572a0-e2ec-45d6-b8db-c100d14b8ef2
description: Detects NetNTLM downgrade attack
references:
    - https://www.optiv.com/blog/post-exploitation-using-netntlm-downgrade-attacks
author: Florian Roth
date: 2018/03/20
modified: 2020/08/23
tags:
    - attack.defense_evasion
    - attack.t1089          # an old one
    - attack.t1562.001
    - attack.t1112
detection:
    condition: 1 of them
falsepositives:
    - Unknown
level: critical
---
logsource:
    product: windows
    service: sysmon
detection:
    selection1:
        EventID: 13
        TargetObject: 
            - '*SYSTEM\\*ControlSet*\Control\Lsa\lmcompatibilitylevel'
            - '*SYSTEM\\*ControlSet*\Control\Lsa*\NtlmMinClientSec'
            - '*SYSTEM\\*ControlSet*\Control\Lsa*\RestrictSendingNTLMTraffic'
---
# Windows Security Eventlog: Process Creation with Full Command Line
logsource:
    product: windows
    service: security
    definition: 'Requirements: Audit Policy : Object Access > Audit Registry (Success)'
detection:
    selection2:
        EventID: 4657
        ObjectName: '\REGISTRY\MACHINE\SYSTEM\\*ControlSet*\Control\Lsa*'
        ObjectValueName: 
            - 'LmCompatibilityLevel'
            - 'NtlmMinClientSec'
            - 'RestrictSendingNTLMTraffic'

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "13" -and ($_.message -match "TargetObject.*.*SYSTEM\\.*ControlSet.*\\Control\\Lsa\\lmcompatibilitylevel" -or $_.message -match "TargetObject.*.*SYSTEM\\.*ControlSet.*\\Control\\Lsa.*\\NtlmMinClientSec" -or $_.message -match "TargetObject.*.*SYSTEM\\.*ControlSet.*\\Control\\Lsa.*\\RestrictSendingNTLMTraffic")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
Get-WinEvent -LogName Security | where {($_.ID -eq "4657" -and $_.message -match "ObjectName.*\\REGISTRY\\MACHINE\\SYSTEM\\.*ControlSet.*\\Control\\Lsa.*" -and ($_.message -match "LmCompatibilityLevel" -or $_.message -match "NtlmMinClientSec" -or $_.message -match "RestrictSendingNTLMTraffic")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND winlog.event_id:"13" AND winlog.event_data.TargetObject.keyword:(*SYSTEM\\*ControlSet*\\Control\\Lsa\\lmcompatibilitylevel OR *SYSTEM\\*ControlSet*\\Control\\Lsa*\\NtlmMinClientSec OR *SYSTEM\\*ControlSet*\\Control\\Lsa*\\RestrictSendingNTLMTraffic))
(winlog.channel:"Security" AND winlog.event_id:"4657" AND winlog.event_data.ObjectName.keyword:\\REGISTRY\\MACHINE\\SYSTEM\\*ControlSet*\\Control\\Lsa* AND winlog.event_data.ObjectValueName:("LmCompatibilityLevel" OR "NtlmMinClientSec" OR "RestrictSendingNTLMTraffic"))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/d67572a0-e2ec-45d6-b8db-c100d14b8ef2 <<EOF
{
  "metadata": {
    "title": "NetNTLM Downgrade Attack",
    "description": "Detects NetNTLM downgrade attack",
    "tags": [
      "attack.defense_evasion",
      "attack.t1089",
      "attack.t1562.001",
      "attack.t1112"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"13\" AND winlog.event_data.TargetObject.keyword:(*SYSTEM\\\\*ControlSet*\\\\Control\\\\Lsa\\\\lmcompatibilitylevel OR *SYSTEM\\\\*ControlSet*\\\\Control\\\\Lsa*\\\\NtlmMinClientSec OR *SYSTEM\\\\*ControlSet*\\\\Control\\\\Lsa*\\\\RestrictSendingNTLMTraffic))"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"13\" AND winlog.event_data.TargetObject.keyword:(*SYSTEM\\\\*ControlSet*\\\\Control\\\\Lsa\\\\lmcompatibilitylevel OR *SYSTEM\\\\*ControlSet*\\\\Control\\\\Lsa*\\\\NtlmMinClientSec OR *SYSTEM\\\\*ControlSet*\\\\Control\\\\Lsa*\\\\RestrictSendingNTLMTraffic))",
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
        "subject": "Sigma Rule 'NetNTLM Downgrade Attack'",
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
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/d67572a0-e2ec-45d6-b8db-c100d14b8ef2-2 <<EOF
{
  "metadata": {
    "title": "NetNTLM Downgrade Attack",
    "description": "Detects NetNTLM downgrade attack",
    "tags": [
      "attack.defense_evasion",
      "attack.t1089",
      "attack.t1562.001",
      "attack.t1112"
    ],
    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"4657\" AND winlog.event_data.ObjectName.keyword:\\\\REGISTRY\\\\MACHINE\\\\SYSTEM\\\\*ControlSet*\\\\Control\\\\Lsa* AND winlog.event_data.ObjectValueName:(\"LmCompatibilityLevel\" OR \"NtlmMinClientSec\" OR \"RestrictSendingNTLMTraffic\"))"
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
                    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"4657\" AND winlog.event_data.ObjectName.keyword:\\\\REGISTRY\\\\MACHINE\\\\SYSTEM\\\\*ControlSet*\\\\Control\\\\Lsa* AND winlog.event_data.ObjectValueName:(\"LmCompatibilityLevel\" OR \"NtlmMinClientSec\" OR \"RestrictSendingNTLMTraffic\"))",
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
        "subject": "Sigma Rule 'NetNTLM Downgrade Attack'",
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
(EventID:"13" AND TargetObject.keyword:(*SYSTEM\\*ControlSet*\\Control\\Lsa\\lmcompatibilitylevel *SYSTEM\\*ControlSet*\\Control\\Lsa*\\NtlmMinClientSec *SYSTEM\\*ControlSet*\\Control\\Lsa*\\RestrictSendingNTLMTraffic))
(EventID:"4657" AND ObjectName.keyword:\\REGISTRY\\MACHINE\\SYSTEM\\*ControlSet*\\Control\\Lsa* AND ObjectValueName:("LmCompatibilityLevel" "NtlmMinClientSec" "RestrictSendingNTLMTraffic"))
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="13" (TargetObject="*SYSTEM\\*ControlSet*\\Control\\Lsa\\lmcompatibilitylevel" OR TargetObject="*SYSTEM\\*ControlSet*\\Control\\Lsa*\\NtlmMinClientSec" OR TargetObject="*SYSTEM\\*ControlSet*\\Control\\Lsa*\\RestrictSendingNTLMTraffic"))
(source="WinEventLog:Security" EventCode="4657" ObjectName="\\REGISTRY\\MACHINE\\SYSTEM\\*ControlSet*\\Control\\Lsa*" (ObjectValueName="LmCompatibilityLevel" OR ObjectValueName="NtlmMinClientSec" OR ObjectValueName="RestrictSendingNTLMTraffic"))
```


### logpoint
    
```
(event_id="13" TargetObject IN ["*SYSTEM\\*ControlSet*\\Control\\Lsa\\lmcompatibilitylevel", "*SYSTEM\\*ControlSet*\\Control\\Lsa*\\NtlmMinClientSec", "*SYSTEM\\*ControlSet*\\Control\\Lsa*\\RestrictSendingNTLMTraffic"])
(event_source="Microsoft-Windows-Security-Auditing" event_id="4657" ObjectName="\\REGISTRY\\MACHINE\\SYSTEM\\*ControlSet*\\Control\\Lsa*" ObjectValueName IN ["LmCompatibilityLevel", "NtlmMinClientSec", "RestrictSendingNTLMTraffic"])
```


### grep
    
```
grep -P '^(?:.*(?=.*13)(?=.*(?:.*.*SYSTEM\\.*ControlSet.*\Control\Lsa\lmcompatibilitylevel|.*.*SYSTEM\\.*ControlSet.*\Control\Lsa.*\NtlmMinClientSec|.*.*SYSTEM\\.*ControlSet.*\Control\Lsa.*\RestrictSendingNTLMTraffic)))'
grep -P '^(?:.*(?=.*4657)(?=.*\REGISTRY\MACHINE\SYSTEM\\.*ControlSet.*\Control\Lsa.*)(?=.*(?:.*LmCompatibilityLevel|.*NtlmMinClientSec|.*RestrictSendingNTLMTraffic)))'
```



