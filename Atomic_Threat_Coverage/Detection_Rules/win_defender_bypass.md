| Title                    | Windows Defender Exclusion Set       |
|:-------------------------|:------------------|
| **Description**          | Detects scenarios where an windows defender exclusion was added in registry where an entity would want to bypass antivirus scanning from windows defender |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1089: Disabling Security Tools](https://attack.mitre.org/techniques/T1089)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Intended inclusions by administrator</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://www.bleepingcomputer.com/news/security/gootkit-malware-bypasses-windows-defender-by-setting-path-exclusions/](https://www.bleepingcomputer.com/news/security/gootkit-malware-bypasses-windows-defender-by-setting-path-exclusions/)</li></ul>  |
| **Author**               | @BarryShooshooga |
| Other Tags           | <ul><li>attack.t1562.001</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Windows Defender Exclusion Set
id: e9c8808f-4cfb-4ba9-97d4-e5f3beaa244d
description: 'Detects scenarios where an windows defender exclusion was added in registry where an entity would want to bypass antivirus scanning from windows defender'
references:
    - https://www.bleepingcomputer.com/news/security/gootkit-malware-bypasses-windows-defender-by-setting-path-exclusions/
tags:
    - attack.defense_evasion
    - attack.t1089
    - attack.t1562.001
author: "@BarryShooshooga"
date: 2019/10/26
logsource:
    product: windows
    service: security
    definition: 'Requirements: Audit Policy : Security Settings/Local Policies/Audit Policy, Registry System Access Control (SACL): Auditing/User'
detection:
    selection:
        EventID:
            - 4657
            - 4656
            - 4660
            - 4663
        ObjectName|contains: '\Microsoft\Windows Defender\Exclusions\'
    condition: selection
falsepositives:
    - Intended inclusions by administrator
level: high

```





### powershell
    
```
Get-WinEvent -LogName Security | where {(($_.ID -eq "4657" -or $_.ID -eq "4656" -or $_.ID -eq "4660" -or $_.ID -eq "4663") -and $_.message -match "ObjectName.*.*\\Microsoft\\Windows Defender\\Exclusions\\.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND winlog.event_id:("4657" OR "4656" OR "4660" OR "4663") AND winlog.event_data.ObjectName.keyword:*\\Microsoft\\Windows\ Defender\\Exclusions\\*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/e9c8808f-4cfb-4ba9-97d4-e5f3beaa244d <<EOF
{
  "metadata": {
    "title": "Windows Defender Exclusion Set",
    "description": "Detects scenarios where an windows defender exclusion was added in registry where an entity would want to bypass antivirus scanning from windows defender",
    "tags": [
      "attack.defense_evasion",
      "attack.t1089",
      "attack.t1562.001"
    ],
    "query": "(winlog.channel:\"Security\" AND winlog.event_id:(\"4657\" OR \"4656\" OR \"4660\" OR \"4663\") AND winlog.event_data.ObjectName.keyword:*\\\\Microsoft\\\\Windows\\ Defender\\\\Exclusions\\\\*)"
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
                    "query": "(winlog.channel:\"Security\" AND winlog.event_id:(\"4657\" OR \"4656\" OR \"4660\" OR \"4663\") AND winlog.event_data.ObjectName.keyword:*\\\\Microsoft\\\\Windows\\ Defender\\\\Exclusions\\\\*)",
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
        "subject": "Sigma Rule 'Windows Defender Exclusion Set'",
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
(EventID:("4657" "4656" "4660" "4663") AND ObjectName.keyword:*\\Microsoft\\Windows Defender\\Exclusions\\*)
```


### splunk
    
```
(source="WinEventLog:Security" (EventCode="4657" OR EventCode="4656" OR EventCode="4660" OR EventCode="4663") ObjectName="*\\Microsoft\\Windows Defender\\Exclusions\\*")
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id IN ["4657", "4656", "4660", "4663"] ObjectName="*\\Microsoft\\Windows Defender\\Exclusions\\*")
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*4657|.*4656|.*4660|.*4663))(?=.*.*\Microsoft\Windows Defender\Exclusions\\.*))'
```



