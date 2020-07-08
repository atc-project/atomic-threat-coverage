| Title                    | Execution in Webserver Root Folder       |
|:-------------------------|:------------------|
| **Description**          | Detects a suspicious program execution in a web service root folder (filter out false positives) |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1100: Web Shell](https://attack.mitre.org/techniques/T1100)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Various applications</li><li>Tools that include ping or nslookup command invocations</li></ul>  |
| **Development Status**   | experimental |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Florian Roth |
| Other Tags           | <ul><li>attack.t1505.003</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Execution in Webserver Root Folder
id: 35efb964-e6a5-47ad-bbcd-19661854018d
status: experimental
description: Detects a suspicious program execution in a web service root folder (filter out false positives)
author: Florian Roth
date: 2019/01/16
tags:
    - attack.persistence
    - attack.t1100
    - attack.t1505.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image:
            - '*\wwwroot\\*'
            - '*\wmpub\\*'
            - '*\htdocs\\*'
    filter:
        Image:
            - '*bin\\*'
            - '*\Tools\\*'
            - '*\SMSComponent\\*'
        ParentImage:
            - '*\services.exe'
    condition: selection and not filter
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Various applications
    - Tools that include ping or nslookup command invocations
level: medium

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "Image.*.*\\wwwroot\\.*" -or $_.message -match "Image.*.*\\wmpub\\.*" -or $_.message -match "Image.*.*\\htdocs\\.*") -and  -not (($_.message -match "Image.*.*bin\\.*" -or $_.message -match "Image.*.*\\Tools\\.*" -or $_.message -match "Image.*.*\\SMSComponent\\.*") -and ($_.message -match "ParentImage.*.*\\services.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:(*\\wwwroot\\* OR *\\wmpub\\* OR *\\htdocs\\*) AND (NOT (winlog.event_data.Image.keyword:(*bin\\* OR *\\Tools\\* OR *\\SMSComponent\\*) AND winlog.event_data.ParentImage.keyword:(*\\services.exe))))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/35efb964-e6a5-47ad-bbcd-19661854018d <<EOF
{
  "metadata": {
    "title": "Execution in Webserver Root Folder",
    "description": "Detects a suspicious program execution in a web service root folder (filter out false positives)",
    "tags": [
      "attack.persistence",
      "attack.t1100",
      "attack.t1505.003"
    ],
    "query": "(winlog.event_data.Image.keyword:(*\\\\wwwroot\\\\* OR *\\\\wmpub\\\\* OR *\\\\htdocs\\\\*) AND (NOT (winlog.event_data.Image.keyword:(*bin\\\\* OR *\\\\Tools\\\\* OR *\\\\SMSComponent\\\\*) AND winlog.event_data.ParentImage.keyword:(*\\\\services.exe))))"
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
                    "query": "(winlog.event_data.Image.keyword:(*\\\\wwwroot\\\\* OR *\\\\wmpub\\\\* OR *\\\\htdocs\\\\*) AND (NOT (winlog.event_data.Image.keyword:(*bin\\\\* OR *\\\\Tools\\\\* OR *\\\\SMSComponent\\\\*) AND winlog.event_data.ParentImage.keyword:(*\\\\services.exe))))",
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
        "subject": "Sigma Rule 'Execution in Webserver Root Folder'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\n      CommandLine = {{_source.CommandLine}}\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
(Image.keyword:(*\\wwwroot\\* *\\wmpub\\* *\\htdocs\\*) AND (NOT (Image.keyword:(*bin\\* *\\Tools\\* *\\SMSComponent\\*) AND ParentImage.keyword:(*\\services.exe))))
```


### splunk
    
```
((Image="*\\wwwroot\\*" OR Image="*\\wmpub\\*" OR Image="*\\htdocs\\*") NOT ((Image="*bin\\*" OR Image="*\\Tools\\*" OR Image="*\\SMSComponent\\*") (ParentImage="*\\services.exe"))) | table CommandLine,ParentCommandLine
```


### logpoint
    
```
(event_id="1" Image IN ["*\\wwwroot\\*", "*\\wmpub\\*", "*\\htdocs\\*"]  -(Image IN ["*bin\\*", "*\\Tools\\*", "*\\SMSComponent\\*"] ParentImage IN ["*\\services.exe"]))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*\wwwroot\\.*|.*.*\wmpub\\.*|.*.*\htdocs\\.*))(?=.*(?!.*(?:.*(?=.*(?:.*.*bin\\.*|.*.*\Tools\\.*|.*.*\SMSComponent\\.*))(?=.*(?:.*.*\services\.exe))))))'
```



