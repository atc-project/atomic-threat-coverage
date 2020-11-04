| Title                    | Bypass UAC via WSReset.exe       |
|:-------------------------|:------------------|
| **Description**          | Identifies use of WSReset.exe to bypass User Account Control. Adversaries use this technique to execute privileged processes. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1088: Bypass User Account Control](https://attack.mitre.org/techniques/T1088)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1088: Bypass User Account Control](../Triggers/T1088.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://eqllib.readthedocs.io/en/latest/analytics/532b5ed4-7930-11e9-8f5c-d46d6d62a49e.html](https://eqllib.readthedocs.io/en/latest/analytics/532b5ed4-7930-11e9-8f5c-d46d6d62a49e.html)</li></ul>  |
| **Author**               | E.M. Anhaus (orignally from Atomic Blue Detections, Tony Lambert), oscd.community |


## Detection Rules

### Sigma rule

```
title: Bypass UAC via WSReset.exe
id: d797268e-28a9-49a7-b9a8-2f5039011c5c
description: Identifies use of WSReset.exe to bypass User Account Control. Adversaries use this technique to execute privileged processes.
status: experimental
author: E.M. Anhaus (orignally from Atomic Blue Detections, Tony Lambert), oscd.community
date: 2019/10/24
modified: 2019/11/11
references:
    - https://eqllib.readthedocs.io/en/latest/analytics/532b5ed4-7930-11e9-8f5c-d46d6d62a49e.html
tags:
    - attack.privilege_escalation
    - attack.t1088
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\wsreset.exe'
    filter:
        Image|endswith: '\conhost.exe'
    condition: selection and not filter
falsepositives:
    - Unknown
level: high

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "ParentImage.*.*\\wsreset.exe" -and  -not ($_.message -match "Image.*.*\\conhost.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.ParentImage.keyword:*\\wsreset.exe AND (NOT (winlog.event_data.Image.keyword:*\\conhost.exe)))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/d797268e-28a9-49a7-b9a8-2f5039011c5c <<EOF
{
  "metadata": {
    "title": "Bypass UAC via WSReset.exe",
    "description": "Identifies use of WSReset.exe to bypass User Account Control. Adversaries use this technique to execute privileged processes.",
    "tags": [
      "attack.privilege_escalation",
      "attack.t1088"
    ],
    "query": "(winlog.event_data.ParentImage.keyword:*\\\\wsreset.exe AND (NOT (winlog.event_data.Image.keyword:*\\\\conhost.exe)))"
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
                    "query": "(winlog.event_data.ParentImage.keyword:*\\\\wsreset.exe AND (NOT (winlog.event_data.Image.keyword:*\\\\conhost.exe)))",
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
        "subject": "Sigma Rule 'Bypass UAC via WSReset.exe'",
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
(ParentImage.keyword:*\\wsreset.exe AND (NOT (Image.keyword:*\\conhost.exe)))
```


### splunk
    
```
(ParentImage="*\\wsreset.exe" NOT (Image="*\\conhost.exe"))
```


### logpoint
    
```
(ParentImage="*\\wsreset.exe"  -(Image="*\\conhost.exe"))
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\wsreset\.exe)(?=.*(?!.*(?:.*(?=.*.*\conhost\.exe)))))'
```



