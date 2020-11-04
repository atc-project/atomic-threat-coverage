| Title                    | WMI Persistence       |
|:-------------------------|:------------------|
| **Description**          | Detects suspicious WMI event filter and command line event consumer based on event id 5861 and 5859 (Windows 10, 2012 and higher) |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1047: Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0080_5859_wmi_activity](../Data_Needed/DN_0080_5859_wmi_activity.md)</li><li>[DN_0081_5861_wmi_activity](../Data_Needed/DN_0081_5861_wmi_activity.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1047: Windows Management Instrumentation](../Triggers/T1047.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Unknown (data set is too small; further testing needed)</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://twitter.com/mattifestation/status/899646620148539397](https://twitter.com/mattifestation/status/899646620148539397)</li><li>[https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/](https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: WMI Persistence
id: 0b7889b4-5577-4521-a60a-3376ee7f9f7b
status: experimental
description: Detects suspicious WMI event filter and command line event consumer based on event id 5861 and 5859 (Windows 10, 2012 and higher)
author: Florian Roth
date: 2017/08/22
references:
    - https://twitter.com/mattifestation/status/899646620148539397
    - https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/
tags:
    - attack.execution
    - attack.persistence
    - attack.t1047
logsource:
    product: windows
    service: wmi
detection:
    selection:
        EventID: 5861
    keywords:
        Message:
            - '*ActiveScriptEventConsumer*'
            - '*CommandLineEventConsumer*'
            - '*CommandLineTemplate*'
        # - 'Binding EventFilter'  # too many false positive with HP Health Driver
    selection2:
        EventID: 5859
    condition: selection and 1 of keywords or selection2
falsepositives:
    - Unknown (data set is too small; further testing needed)
level: medium

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-WMI-Activity/Operational | where {((($_.ID -eq "5861" -and ($_.message -match "Message.*.*ActiveScriptEventConsumer.*" -or $_.message -match "Message.*.*CommandLineEventConsumer.*" -or $_.message -match "Message.*.*CommandLineTemplate.*")) -or $_.ID -eq "5859")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
((winlog.event_id:"5861" AND winlog.event_data.Message.keyword:(*ActiveScriptEventConsumer* OR *CommandLineEventConsumer* OR *CommandLineTemplate*)) OR winlog.event_id:"5859")
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/0b7889b4-5577-4521-a60a-3376ee7f9f7b <<EOF
{
  "metadata": {
    "title": "WMI Persistence",
    "description": "Detects suspicious WMI event filter and command line event consumer based on event id 5861 and 5859 (Windows 10, 2012 and higher)",
    "tags": [
      "attack.execution",
      "attack.persistence",
      "attack.t1047"
    ],
    "query": "((winlog.event_id:\"5861\" AND winlog.event_data.Message.keyword:(*ActiveScriptEventConsumer* OR *CommandLineEventConsumer* OR *CommandLineTemplate*)) OR winlog.event_id:\"5859\")"
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
                    "query": "((winlog.event_id:\"5861\" AND winlog.event_data.Message.keyword:(*ActiveScriptEventConsumer* OR *CommandLineEventConsumer* OR *CommandLineTemplate*)) OR winlog.event_id:\"5859\")",
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
        "subject": "Sigma Rule 'WMI Persistence'",
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
((EventID:"5861" AND Message.keyword:(*ActiveScriptEventConsumer* *CommandLineEventConsumer* *CommandLineTemplate*)) OR EventID:"5859")
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-WMI-Activity/Operational" ((EventCode="5861" (Message="*ActiveScriptEventConsumer*" OR Message="*CommandLineEventConsumer*" OR Message="*CommandLineTemplate*")) OR EventCode="5859"))
```


### logpoint
    
```
((event_id="5861" Message IN ["*ActiveScriptEventConsumer*", "*CommandLineEventConsumer*", "*CommandLineTemplate*"]) OR event_id="5859")
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*(?=.*5861)(?=.*(?:.*.*ActiveScriptEventConsumer.*|.*.*CommandLineEventConsumer.*|.*.*CommandLineTemplate.*)))|.*5859))'
```



