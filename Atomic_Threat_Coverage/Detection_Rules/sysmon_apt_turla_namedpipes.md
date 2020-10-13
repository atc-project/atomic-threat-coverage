| Title                    | Turla Group Named Pipes       |
|:-------------------------|:------------------|
| **Description**          | Detects a named pipe used by Turla group samples |
| **ATT&amp;CK Tactic**    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| **ATT&amp;CK Technique** |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| **Data Needed**          | <ul><li>[DN_0020_17_windows_sysmon_PipeEvent](../Data_Needed/DN_0020_17_windows_sysmon_PipeEvent.md)</li><li>[DN_0021_18_windows_sysmon_PipeEvent](../Data_Needed/DN_0021_18_windows_sysmon_PipeEvent.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Unkown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[Internal Research](Internal Research)</li></ul>  |
| **Author**               | Markus Neis |
| Other Tags           | <ul><li>attack.g0010</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Turla Group Named Pipes
id: 739915e4-1e70-4778-8b8a-17db02f66db1
status: experimental
description: Detects a named pipe used by Turla group samples
references:
    - Internal Research
date: 2017/11/06
tags:
    - attack.g0010
author: Markus Neis
logsource:
    product: windows
    service: sysmon
    definition: 'Note that you have to configure logging for PipeEvents in Symson config'
detection:
    selection:
        EventID: 
            - 17
            - 18
        PipeName: 
            - '\atctl' # https://www.virustotal.com/#/file/a4ddb2664a6c87a1d3c5da5a5a32a5df9a0b0c8f2e951811bd1ec1d44d42ccf1/detection
            - '\userpipe' # ruag apt case
            - '\iehelper' # ruag apt case
            - '\sdlrpc' # project cobra https://www.gdatasoftware.com/blog/2015/01/23926-analysis-of-project-cobra
            - '\comnap' # https://www.gdatasoftware.com/blog/2015/01/23926-analysis-of-project-cobra
            # - '\rpc'  # may cause too many false positives : http://kb.palisade.com/index.php?pg=kb.page&id=483
    condition: selection
falsepositives:
    - Unkown
level: critical


```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "17" -or $_.ID -eq "18") -and ($_.message -match "\\atctl" -or $_.message -match "\\userpipe" -or $_.message -match "\\iehelper" -or $_.message -match "\\sdlrpc" -or $_.message -match "\\comnap")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND winlog.event_id:("17" OR "18") AND winlog.event_data.PipeName:("\\atctl" OR "\\userpipe" OR "\\iehelper" OR "\\sdlrpc" OR "\\comnap"))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/739915e4-1e70-4778-8b8a-17db02f66db1 <<EOF
{
  "metadata": {
    "title": "Turla Group Named Pipes",
    "description": "Detects a named pipe used by Turla group samples",
    "tags": [
      "attack.g0010"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:(\"17\" OR \"18\") AND winlog.event_data.PipeName:(\"\\\\atctl\" OR \"\\\\userpipe\" OR \"\\\\iehelper\" OR \"\\\\sdlrpc\" OR \"\\\\comnap\"))"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:(\"17\" OR \"18\") AND winlog.event_data.PipeName:(\"\\\\atctl\" OR \"\\\\userpipe\" OR \"\\\\iehelper\" OR \"\\\\sdlrpc\" OR \"\\\\comnap\"))",
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
        "subject": "Sigma Rule 'Turla Group Named Pipes'",
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
(EventID:("17" "18") AND PipeName:("\\atctl" "\\userpipe" "\\iehelper" "\\sdlrpc" "\\comnap"))
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode="17" OR EventCode="18") (PipeName="\\atctl" OR PipeName="\\userpipe" OR PipeName="\\iehelper" OR PipeName="\\sdlrpc" OR PipeName="\\comnap"))
```


### logpoint
    
```
(event_id IN ["17", "18"] PipeName IN ["\\atctl", "\\userpipe", "\\iehelper", "\\sdlrpc", "\\comnap"])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*17|.*18))(?=.*(?:.*\atctl|.*\userpipe|.*\iehelper|.*\sdlrpc|.*\comnap)))'
```



