| Title                    | Terminal Service Process Spawn       |
|:-------------------------|:------------------|
| **Description**          | Detects a process spawned by the terminal service server process (this could be an indicator for an exploitation of CVE-2019-0708) |
| **ATT&amp;CK Tactic**    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| **ATT&amp;CK Technique** |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| **Data Needed**          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://securingtomorrow.mcafee.com/other-blogs/mcafee-labs/rdp-stands-for-really-do-patch-understanding-the-wormable-rdp-vulnerability-cve-2019-0708/](https://securingtomorrow.mcafee.com/other-blogs/mcafee-labs/rdp-stands-for-really-do-patch-understanding-the-wormable-rdp-vulnerability-cve-2019-0708/)</li></ul>  |
| **Author**               | Florian Roth |
| Other Tags           | <ul><li>car.2013-07-002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Terminal Service Process Spawn
id: 1012f107-b8f1-4271-af30-5aed2de89b39
status: experimental
description: Detects a process spawned by the terminal service server process (this could be an indicator for an exploitation of CVE-2019-0708)
references:
    - https://securingtomorrow.mcafee.com/other-blogs/mcafee-labs/rdp-stands-for-really-do-patch-understanding-the-wormable-rdp-vulnerability-cve-2019-0708/
author: Florian Roth
date: 2019/05/22
tags:
    - car.2013-07-002
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        ParentCommandLine: '*\svchost.exe*termsvcs'
    filter:
        Image: '*\rdpclip.exe'
    condition: selection and not filter
falsepositives:
    - Unknown
level: high


```





### powershell
    
```
Get-WinEvent | where {($_.message -match "ParentCommandLine.*.*\\svchost.exe.*termsvcs" -and  -not ($_.message -match "Image.*.*\\rdpclip.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.ParentCommandLine.keyword:*\\svchost.exe*termsvcs AND (NOT (winlog.event_data.Image.keyword:*\\rdpclip.exe)))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/1012f107-b8f1-4271-af30-5aed2de89b39 <<EOF
{
  "metadata": {
    "title": "Terminal Service Process Spawn",
    "description": "Detects a process spawned by the terminal service server process (this could be an indicator for an exploitation of CVE-2019-0708)",
    "tags": [
      "car.2013-07-002"
    ],
    "query": "(winlog.event_data.ParentCommandLine.keyword:*\\\\svchost.exe*termsvcs AND (NOT (winlog.event_data.Image.keyword:*\\\\rdpclip.exe)))"
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
                    "query": "(winlog.event_data.ParentCommandLine.keyword:*\\\\svchost.exe*termsvcs AND (NOT (winlog.event_data.Image.keyword:*\\\\rdpclip.exe)))",
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
        "subject": "Sigma Rule 'Terminal Service Process Spawn'",
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
(ParentCommandLine.keyword:*\\svchost.exe*termsvcs AND (NOT (Image.keyword:*\\rdpclip.exe)))
```


### splunk
    
```
(ParentCommandLine="*\\svchost.exe*termsvcs" NOT (Image="*\\rdpclip.exe"))
```


### logpoint
    
```
(ParentCommandLine="*\\svchost.exe*termsvcs"  -(Image="*\\rdpclip.exe"))
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\svchost\.exe.*termsvcs)(?=.*(?!.*(?:.*(?=.*.*\rdpclip\.exe)))))'
```



