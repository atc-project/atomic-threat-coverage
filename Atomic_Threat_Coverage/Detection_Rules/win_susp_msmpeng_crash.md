| Title                    | Microsoft Malware Protection Engine Crash       |
|:-------------------------|:------------------|
| **Description**          | This rule detects a suspicious crash of the Microsoft Malware Protection Engine |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1089: Disabling Security Tools](https://attack.mitre.org/techniques/T1089)</li><li>[T1211: Exploitation for Defense Evasion](https://attack.mitre.org/techniques/T1211)</li><li>[T1562.001: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              | <ul><li>[T1562.001: Disable or Modify Tools](../Triggers/T1562.001.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>MsMpEng.exe can crash when C:\ is full</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://bugs.chromium.org/p/project-zero/issues/detail?id=1252&desc=5](https://bugs.chromium.org/p/project-zero/issues/detail?id=1252&desc=5)</li><li>[https://technet.microsoft.com/en-us/library/security/4022344](https://technet.microsoft.com/en-us/library/security/4022344)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Microsoft Malware Protection Engine Crash
id: 6c82cf5c-090d-4d57-9188-533577631108
description: This rule detects a suspicious crash of the Microsoft Malware Protection Engine
tags:
    - attack.defense_evasion
    - attack.t1089          # an old one
    - attack.t1211
    - attack.t1562.001
status: experimental
date: 2017/05/09
references:
    - https://bugs.chromium.org/p/project-zero/issues/detail?id=1252&desc=5
    - https://technet.microsoft.com/en-us/library/security/4022344
author: Florian Roth
logsource:
    product: windows
    service: application
detection:
    selection1:
        Source: 'Application Error'
        EventID: 1000
    selection2:
        Source: 'Windows Error Reporting'
        EventID: 1001
    keywords:
        Message:
            - '*MsMpEng.exe*'
            - '*mpengine.dll*'
    condition: 1 of selection* and all of keywords
falsepositives:
    - MsMpEng.exe can crash when C:\ is full
level: high

```





### powershell
    
```
Get-WinEvent -LogName Application | where {((($_.message -match "Source.*Application Error" -and $_.ID -eq "1000") -or ($_.message -match "Source.*Windows Error Reporting" -and $_.ID -eq "1001")) -and ($_.message -match ".*MsMpEng.exe.*" -or $_.message -match ".*mpengine.dll.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Application" AND ((winlog.event_data.Source:"Application\ Error" AND winlog.event_id:"1000") OR (winlog.event_data.Source:"Windows\ Error\ Reporting" AND winlog.event_id:"1001")) AND Message.keyword:(*MsMpEng.exe* OR *mpengine.dll*))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/6c82cf5c-090d-4d57-9188-533577631108 <<EOF
{
  "metadata": {
    "title": "Microsoft Malware Protection Engine Crash",
    "description": "This rule detects a suspicious crash of the Microsoft Malware Protection Engine",
    "tags": [
      "attack.defense_evasion",
      "attack.t1089",
      "attack.t1211",
      "attack.t1562.001"
    ],
    "query": "(winlog.channel:\"Application\" AND ((winlog.event_data.Source:\"Application\\ Error\" AND winlog.event_id:\"1000\") OR (winlog.event_data.Source:\"Windows\\ Error\\ Reporting\" AND winlog.event_id:\"1001\")) AND Message.keyword:(*MsMpEng.exe* OR *mpengine.dll*))"
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
                    "query": "(winlog.channel:\"Application\" AND ((winlog.event_data.Source:\"Application\\ Error\" AND winlog.event_id:\"1000\") OR (winlog.event_data.Source:\"Windows\\ Error\\ Reporting\" AND winlog.event_id:\"1001\")) AND Message.keyword:(*MsMpEng.exe* OR *mpengine.dll*))",
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
        "subject": "Sigma Rule 'Microsoft Malware Protection Engine Crash'",
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
(((Source:"Application Error" AND EventID:"1000") OR (Source:"Windows Error Reporting" AND EventID:"1001")) AND Message.keyword:(*MsMpEng.exe* *mpengine.dll*))
```


### splunk
    
```
(source="WinEventLog:Application" ((Source="Application Error" EventCode="1000") OR (Source="Windows Error Reporting" EventCode="1001")) (Message="*MsMpEng.exe*" OR Message="*mpengine.dll*"))
```


### logpoint
    
```
(((Source="Application Error" event_id="1000") OR (Source="Windows Error Reporting" event_id="1001")) Message IN ["*MsMpEng.exe*", "*mpengine.dll*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?:.*(?:.*(?=.*Application Error)(?=.*1000))|.*(?:.*(?=.*Windows Error Reporting)(?=.*1001)))))(?=.*(?:.*.*MsMpEng\.exe.*|.*.*mpengine\.dll.*)))'
```



