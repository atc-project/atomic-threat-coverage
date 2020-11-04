| Title                    | Suspicious RUN Key from Download       |
|:-------------------------|:------------------|
| **Description**          | Detects the suspicious RUN keys created by software located in Download or temporary Outlook/Internet Explorer directories |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1060: Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1060)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1060: Registry Run Keys / Startup Folder](../Triggers/T1060.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Software installers downloaded and used by users</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://app.any.run/tasks/c5bef5b7-f484-4c43-9cf3-d5c5c7839def/](https://app.any.run/tasks/c5bef5b7-f484-4c43-9cf3-d5c5c7839def/)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Suspicious RUN Key from Download
id: 9c5037d1-c568-49b3-88c7-9846a5bdc2be
status: experimental
description: Detects the suspicious RUN keys created by software located in Download or temporary Outlook/Internet Explorer directories
references:
    - https://app.any.run/tasks/c5bef5b7-f484-4c43-9cf3-d5c5c7839def/
author: Florian Roth
date: 2019/10/01
tags:
    - attack.persistence
    - attack.t1060
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 13
        Image: 
            - '*\Downloads\\*'
            - '*\Temporary Internet Files\Content.Outlook\\*'
            - '*\Local Settings\Temporary Internet Files\\*'
        TargetObject: '*\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\\*'
    condition: selection
falsepositives:
    - Software installers downloaded and used by users
level: high
```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "13" -and ($_.message -match "Image.*.*\\Downloads\\.*" -or $_.message -match "Image.*.*\\Temporary Internet Files\\Content.Outlook\\.*" -or $_.message -match "Image.*.*\\Local Settings\\Temporary Internet Files\\.*") -and $_.message -match "TargetObject.*.*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND winlog.event_id:"13" AND winlog.event_data.Image.keyword:(*\\Downloads\\* OR *\\Temporary\ Internet\ Files\\Content.Outlook\\* OR *\\Local\ Settings\\Temporary\ Internet\ Files\\*) AND winlog.event_data.TargetObject.keyword:*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/9c5037d1-c568-49b3-88c7-9846a5bdc2be <<EOF
{
  "metadata": {
    "title": "Suspicious RUN Key from Download",
    "description": "Detects the suspicious RUN keys created by software located in Download or temporary Outlook/Internet Explorer directories",
    "tags": [
      "attack.persistence",
      "attack.t1060"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"13\" AND winlog.event_data.Image.keyword:(*\\\\Downloads\\\\* OR *\\\\Temporary\\ Internet\\ Files\\\\Content.Outlook\\\\* OR *\\\\Local\\ Settings\\\\Temporary\\ Internet\\ Files\\\\*) AND winlog.event_data.TargetObject.keyword:*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\*)"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"13\" AND winlog.event_data.Image.keyword:(*\\\\Downloads\\\\* OR *\\\\Temporary\\ Internet\\ Files\\\\Content.Outlook\\\\* OR *\\\\Local\\ Settings\\\\Temporary\\ Internet\\ Files\\\\*) AND winlog.event_data.TargetObject.keyword:*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\*)",
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
        "subject": "Sigma Rule 'Suspicious RUN Key from Download'",
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
(EventID:"13" AND Image.keyword:(*\\Downloads\\* *\\Temporary Internet Files\\Content.Outlook\\* *\\Local Settings\\Temporary Internet Files\\*) AND TargetObject.keyword:*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\*)
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="13" (Image="*\\Downloads\\*" OR Image="*\\Temporary Internet Files\\Content.Outlook\\*" OR Image="*\\Local Settings\\Temporary Internet Files\\*") TargetObject="*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\*")
```


### logpoint
    
```
(event_id="13" Image IN ["*\\Downloads\\*", "*\\Temporary Internet Files\\Content.Outlook\\*", "*\\Local Settings\\Temporary Internet Files\\*"] TargetObject="*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\*")
```


### grep
    
```
grep -P '^(?:.*(?=.*13)(?=.*(?:.*.*\Downloads\\.*|.*.*\Temporary Internet Files\Content\.Outlook\\.*|.*.*\Local Settings\Temporary Internet Files\\.*))(?=.*.*\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\\.*))'
```



