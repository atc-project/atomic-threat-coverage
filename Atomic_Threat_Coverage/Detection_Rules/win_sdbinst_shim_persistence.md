| Title                    | Possible Shim Database Persistence via sdbinst.exe       |
|:-------------------------|:------------------|
| **Description**          | Detects installation of a new shim using sdbinst.exe. A shim can be used to load malicious DLLs into applications. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1138: Application Shimming](https://attack.mitre.org/techniques/T1138)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html](https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html)</li></ul>  |
| **Author**               | Markus Neis |
| Other Tags           | <ul><li>attack.t1546.011</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Possible Shim Database Persistence via sdbinst.exe
id: 517490a7-115a-48c6-8862-1a481504d5a8
status: experimental
description: Detects installation of a new shim using sdbinst.exe. A shim can be used to load malicious DLLs into applications.
references:
    - https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html
tags:
    - attack.persistence
    - attack.t1138
    - attack.t1546.011
author: Markus Neis
date: 2019/01/16
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image:
            - '*\sdbinst.exe'
        CommandLine:
            - '*.sdb*'
    condition: selection
falsepositives:
    - Unknown
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "Image.*.*\\sdbinst.exe") -and ($_.message -match "CommandLine.*.*.sdb.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:(*\\sdbinst.exe) AND winlog.event_data.CommandLine.keyword:(*.sdb*))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/517490a7-115a-48c6-8862-1a481504d5a8 <<EOF
{
  "metadata": {
    "title": "Possible Shim Database Persistence via sdbinst.exe",
    "description": "Detects installation of a new shim using sdbinst.exe. A shim can be used to load malicious DLLs into applications.",
    "tags": [
      "attack.persistence",
      "attack.t1138",
      "attack.t1546.011"
    ],
    "query": "(winlog.event_data.Image.keyword:(*\\\\sdbinst.exe) AND winlog.event_data.CommandLine.keyword:(*.sdb*))"
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
                    "query": "(winlog.event_data.Image.keyword:(*\\\\sdbinst.exe) AND winlog.event_data.CommandLine.keyword:(*.sdb*))",
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
        "subject": "Sigma Rule 'Possible Shim Database Persistence via sdbinst.exe'",
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
(Image.keyword:(*\\sdbinst.exe) AND CommandLine.keyword:(*.sdb*))
```


### splunk
    
```
((Image="*\\sdbinst.exe") (CommandLine="*.sdb*"))
```


### logpoint
    
```
(event_id="1" Image IN ["*\\sdbinst.exe"] CommandLine IN ["*.sdb*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*\sdbinst\.exe))(?=.*(?:.*.*\.sdb.*)))'
```



