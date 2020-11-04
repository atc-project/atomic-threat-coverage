| Title                    | LSASS Access Detected via Attack Surface Reduction       |
|:-------------------------|:------------------|
| **Description**          | Detects Access to LSASS Process |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1003: OS Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              | <ul><li>[T1003: OS Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Google Chrome GoogleUpdate.exe</li><li>Some Taskmgr.exe related activity</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-exploit-guard/attack-surface-reduction-exploit-guard?WT.mc_id=twitter](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-exploit-guard/attack-surface-reduction-exploit-guard?WT.mc_id=twitter)</li></ul>  |
| **Author**               | Markus Neis |


## Detection Rules

### Sigma rule

```
title: LSASS Access Detected via Attack Surface Reduction
id: a0a278fe-2c0e-4de2-ac3c-c68b08a9ba98
description: Detects Access to LSASS Process
status: experimental
references:
    - https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-exploit-guard/attack-surface-reduction-exploit-guard?WT.mc_id=twitter
author: Markus Neis
date: 2018/08/26
tags:
    - attack.credential_access
    - attack.t1003
# Defender Attack Surface Reduction
logsource:
    product: windows_defender
    definition: 'Requirements:Enabled Block credential stealing from the Windows local security authority subsystem (lsass.exe) from Attack Surface Reduction (GUID: 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2)'
detection:
    selection:
        EventID: 1121
        Path: '*\lsass.exe'
    condition: selection
falsepositives:
    - Google Chrome GoogleUpdate.exe
    - Some Taskmgr.exe related activity
level: high

```





### powershell
    
```
Get-WinEvent | where {($_.ID -eq "1121" -and $_.message -match "Path.*.*\\lsass.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_id:"1121" AND winlog.event_data.Path.keyword:*\\lsass.exe)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/a0a278fe-2c0e-4de2-ac3c-c68b08a9ba98 <<EOF
{
  "metadata": {
    "title": "LSASS Access Detected via Attack Surface Reduction",
    "description": "Detects Access to LSASS Process",
    "tags": [
      "attack.credential_access",
      "attack.t1003"
    ],
    "query": "(winlog.event_id:\"1121\" AND winlog.event_data.Path.keyword:*\\\\lsass.exe)"
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
                    "query": "(winlog.event_id:\"1121\" AND winlog.event_data.Path.keyword:*\\\\lsass.exe)",
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
        "subject": "Sigma Rule 'LSASS Access Detected via Attack Surface Reduction'",
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
(EventID:"1121" AND Path.keyword:*\\lsass.exe)
```


### splunk
    
```
(EventCode="1121" Path="*\\lsass.exe")
```


### logpoint
    
```
(event_id="1121" Path="*\\lsass.exe")
```


### grep
    
```
grep -P '^(?:.*(?=.*1121)(?=.*.*\lsass\.exe))'
```



