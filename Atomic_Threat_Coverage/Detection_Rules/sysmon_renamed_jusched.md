| Title                    | Renamed jusched.exe       |
|:-------------------------|:------------------|
| **Description**          | Detects renamed jusched.exe used by cobalt group |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1036: Masquerading](https://attack.mitre.org/techniques/T1036)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1036: Masquerading](../Triggers/T1036.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>penetration tests, red teaming</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.bitdefender.com/files/News/CaseStudies/study/262/Bitdefender-WhitePaper-An-APT-Blueprint-Gaining-New-Visibility-into-Financial-Threats-interactive.pdf](https://www.bitdefender.com/files/News/CaseStudies/study/262/Bitdefender-WhitePaper-An-APT-Blueprint-Gaining-New-Visibility-into-Financial-Threats-interactive.pdf)</li></ul>  |
| **Author**               | Markus Neis, Swisscom |


## Detection Rules

### Sigma rule

```
title: Renamed jusched.exe 
status: experimental
id: edd8a48c-1b9f-4ba1-83aa-490338cd1ccb
description: Detects renamed jusched.exe used by cobalt group 
references:
    - https://www.bitdefender.com/files/News/CaseStudies/study/262/Bitdefender-WhitePaper-An-APT-Blueprint-Gaining-New-Visibility-into-Financial-Threats-interactive.pdf
tags:
    - attack.t1036 
    - attack.execution
author: Markus Neis, Swisscom
date: 2019/06/04
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        Description: Java Update Scheduler
    selection2:
        Description: Java(TM) Update Scheduler
    filter:
        Image|endswith:
            - '\jusched.exe'
    condition: (selection1 or selection2) and not filter
falsepositives:
    - penetration tests, red teaming
level: high

```





### powershell
    
```
Get-WinEvent | where {(($_.message -match "Description.*Java Update Scheduler" -or $_.message -match "Description.*Java(TM) Update Scheduler") -and  -not (($_.message -match "Image.*.*\\jusched.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
((winlog.event_data.Description:"Java\ Update\ Scheduler" OR winlog.event_data.Description:"Java\(TM\)\ Update\ Scheduler") AND (NOT (winlog.event_data.Image.keyword:(*\\jusched.exe))))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/edd8a48c-1b9f-4ba1-83aa-490338cd1ccb <<EOF
{
  "metadata": {
    "title": "Renamed jusched.exe",
    "description": "Detects renamed jusched.exe used by cobalt group",
    "tags": [
      "attack.t1036",
      "attack.execution"
    ],
    "query": "((winlog.event_data.Description:\"Java\\ Update\\ Scheduler\" OR winlog.event_data.Description:\"Java\\(TM\\)\\ Update\\ Scheduler\") AND (NOT (winlog.event_data.Image.keyword:(*\\\\jusched.exe))))"
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
                    "query": "((winlog.event_data.Description:\"Java\\ Update\\ Scheduler\" OR winlog.event_data.Description:\"Java\\(TM\\)\\ Update\\ Scheduler\") AND (NOT (winlog.event_data.Image.keyword:(*\\\\jusched.exe))))",
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
        "subject": "Sigma Rule 'Renamed jusched.exe'",
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
((Description:"Java Update Scheduler" OR Description:"Java\(TM\) Update Scheduler") AND (NOT (Image.keyword:(*\\jusched.exe))))
```


### splunk
    
```
((Description="Java Update Scheduler" OR Description="Java(TM) Update Scheduler") NOT ((Image="*\\jusched.exe")))
```


### logpoint
    
```
((Description="Java Update Scheduler" OR Description="Java(TM) Update Scheduler")  -(Image IN ["*\\jusched.exe"]))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?:.*Java Update Scheduler|.*Java\(TM\) Update Scheduler)))(?=.*(?!.*(?:.*(?=.*(?:.*.*\jusched\.exe))))))'
```



