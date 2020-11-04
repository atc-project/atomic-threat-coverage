| Title                    | Suspect Svchost Memory Asccess       |
|:-------------------------|:------------------|
| **Description**          | Detects suspect access to svchost process memory such as that used by Invoke-Phantom to kill the winRM windows event logging service. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1089: Disabling Security Tools](https://attack.mitre.org/techniques/T1089)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0014_10_windows_sysmon_ProcessAccess](../Data_Needed/DN_0014_10_windows_sysmon_ProcessAccess.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1089: Disabling Security Tools](../Triggers/T1089.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/hlldz/Invoke-Phant0m](https://github.com/hlldz/Invoke-Phant0m)</li><li>[https://twitter.com/timbmsft/status/900724491076214784](https://twitter.com/timbmsft/status/900724491076214784)</li></ul>  |
| **Author**               | Tim Burrell |


## Detection Rules

### Sigma rule

```
title: Suspect Svchost Memory Asccess
id: 166e9c50-8cd9-44af-815d-d1f0c0e90dde
status: experimental
description: Detects suspect access to svchost process memory such as that used by Invoke-Phantom to kill the winRM windows event logging service.
author: Tim Burrell
date: 2020/01/02
references:
    - https://github.com/hlldz/Invoke-Phant0m
    - https://twitter.com/timbmsft/status/900724491076214784
tags:
    - attack.t1089
    - attack.defense_evasion
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 10
        TargetImage: '*\windows\system32\svchost.exe'
        GrantedAccess: '0x1f3fff'
        CallTrace:
         - '*unknown*'
    condition: selection
falsepositives:
    - unknown
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "10" -and $_.message -match "TargetImage.*.*\\windows\\system32\\svchost.exe" -and $_.message -match "GrantedAccess.*0x1f3fff" -and ($_.message -match "CallTrace.*.*unknown.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND winlog.event_id:"10" AND winlog.event_data.TargetImage.keyword:*\\windows\\system32\\svchost.exe AND winlog.event_data.GrantedAccess:"0x1f3fff" AND winlog.event_data.CallTrace.keyword:(*unknown*))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/166e9c50-8cd9-44af-815d-d1f0c0e90dde <<EOF
{
  "metadata": {
    "title": "Suspect Svchost Memory Asccess",
    "description": "Detects suspect access to svchost process memory such as that used by Invoke-Phantom to kill the winRM windows event logging service.",
    "tags": [
      "attack.t1089",
      "attack.defense_evasion"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"10\" AND winlog.event_data.TargetImage.keyword:*\\\\windows\\\\system32\\\\svchost.exe AND winlog.event_data.GrantedAccess:\"0x1f3fff\" AND winlog.event_data.CallTrace.keyword:(*unknown*))"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"10\" AND winlog.event_data.TargetImage.keyword:*\\\\windows\\\\system32\\\\svchost.exe AND winlog.event_data.GrantedAccess:\"0x1f3fff\" AND winlog.event_data.CallTrace.keyword:(*unknown*))",
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
        "subject": "Sigma Rule 'Suspect Svchost Memory Asccess'",
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
(EventID:"10" AND TargetImage.keyword:*\\windows\\system32\\svchost.exe AND GrantedAccess:"0x1f3fff" AND CallTrace.keyword:(*unknown*))
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="10" TargetImage="*\\windows\\system32\\svchost.exe" GrantedAccess="0x1f3fff" (CallTrace="*unknown*"))
```


### logpoint
    
```
(event_id="10" TargetImage="*\\windows\\system32\\svchost.exe" GrantedAccess="0x1f3fff" CallTrace IN ["*unknown*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*10)(?=.*.*\windows\system32\svchost\.exe)(?=.*0x1f3fff)(?=.*(?:.*.*unknown.*)))'
```



