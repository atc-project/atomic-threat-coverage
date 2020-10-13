| Title                    | CrackMapExecWin       |
|:-------------------------|:------------------|
| **Description**          | Detects CrackMapExecWin Activity as Described by NCSC |
| **ATT&amp;CK Tactic**    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| **ATT&amp;CK Technique** |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| **Data Needed**          | <ul><li>[DN_0001_4688_windows_process_creation](../Data_Needed/DN_0001_4688_windows_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>None</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control](https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control)</li></ul>  |
| **Author**               | Markus Neis |
| Other Tags           | <ul><li>attack.g0035</li></ul> | 

## Detection Rules

### Sigma rule

```
title: CrackMapExecWin
id: 04d9079e-3905-4b70-ad37-6bdf11304965
description: Detects CrackMapExecWin Activity as Described by NCSC
status: experimental
references:
    - https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control
tags:
    - attack.g0035
author: Markus Neis
date: 2018/04/08
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image:
            - '*\crackmapexec.exe'
    condition: selection
falsepositives:
    - None
level: critical

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "Image.*.*\\crackmapexec.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.Image.keyword:(*\\crackmapexec.exe)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/04d9079e-3905-4b70-ad37-6bdf11304965 <<EOF
{
  "metadata": {
    "title": "CrackMapExecWin",
    "description": "Detects CrackMapExecWin Activity as Described by NCSC",
    "tags": [
      "attack.g0035"
    ],
    "query": "winlog.event_data.Image.keyword:(*\\\\crackmapexec.exe)"
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
                    "query": "winlog.event_data.Image.keyword:(*\\\\crackmapexec.exe)",
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
        "subject": "Sigma Rule 'CrackMapExecWin'",
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
Image.keyword:(*\\crackmapexec.exe)
```


### splunk
    
```
(Image="*\\crackmapexec.exe")
```


### logpoint
    
```
Image IN ["*\\crackmapexec.exe"]
```


### grep
    
```
grep -P '^(?:.*.*\crackmapexec\.exe)'
```



