| Title                    | Secure Deletion with SDelete       |
|:-------------------------|:------------------|
| **Description**          | Detects renaming of file while deletion with SDelete tool |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1107: File Deletion](https://attack.mitre.org/techniques/T1107)</li><li>[T1066: Indicator Removal from Tools](https://attack.mitre.org/techniques/T1066)</li><li>[T1027: Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              | <ul><li>[T1027: Obfuscated Files or Information](../Triggers/T1027.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Legitime usage of SDelete</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://jpcertcc.github.io/ToolAnalysisResultSheet](https://jpcertcc.github.io/ToolAnalysisResultSheet)</li><li>[https://www.jpcert.or.jp/english/pub/sr/ir_research.html](https://www.jpcert.or.jp/english/pub/sr/ir_research.html)</li><li>[https://technet.microsoft.com/en-us/en-en/sysinternals/sdelete.aspx](https://technet.microsoft.com/en-us/en-en/sysinternals/sdelete.aspx)</li></ul>  |
| **Author**               | Thomas Patzke |
| Other Tags           | <ul><li>attack.s0195</li><li>attack.t1551.004</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Secure Deletion with SDelete
id: 39a80702-d7ca-4a83-b776-525b1f86a36d
status: experimental
description: Detects renaming of file while deletion with SDelete tool
author: Thomas Patzke
date: 2017/06/14
references:
    - https://jpcertcc.github.io/ToolAnalysisResultSheet
    - https://www.jpcert.or.jp/english/pub/sr/ir_research.html
    - https://technet.microsoft.com/en-us/en-en/sysinternals/sdelete.aspx
tags:
    - attack.defense_evasion
    - attack.t1107
    - attack.t1066
    - attack.s0195
    - attack.t1551.004
    - attack.t1027
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 4656
            - 4663
            - 4658
        ObjectName:
            - '*.AAA'
            - '*.ZZZ'
    condition: selection
falsepositives:
    - Legitime usage of SDelete
level: medium

```





### powershell
    
```
Get-WinEvent -LogName Security | where {(($_.ID -eq "4656" -or $_.ID -eq "4663" -or $_.ID -eq "4658") -and ($_.message -match "ObjectName.*.*.AAA" -or $_.message -match "ObjectName.*.*.ZZZ")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND winlog.event_id:("4656" OR "4663" OR "4658") AND winlog.event_data.ObjectName.keyword:(*.AAA OR *.ZZZ))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/39a80702-d7ca-4a83-b776-525b1f86a36d <<EOF
{
  "metadata": {
    "title": "Secure Deletion with SDelete",
    "description": "Detects renaming of file while deletion with SDelete tool",
    "tags": [
      "attack.defense_evasion",
      "attack.t1107",
      "attack.t1066",
      "attack.s0195",
      "attack.t1551.004",
      "attack.t1027"
    ],
    "query": "(winlog.channel:\"Security\" AND winlog.event_id:(\"4656\" OR \"4663\" OR \"4658\") AND winlog.event_data.ObjectName.keyword:(*.AAA OR *.ZZZ))"
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
                    "query": "(winlog.channel:\"Security\" AND winlog.event_id:(\"4656\" OR \"4663\" OR \"4658\") AND winlog.event_data.ObjectName.keyword:(*.AAA OR *.ZZZ))",
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
        "subject": "Sigma Rule 'Secure Deletion with SDelete'",
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
(EventID:("4656" "4663" "4658") AND ObjectName.keyword:(*.AAA *.ZZZ))
```


### splunk
    
```
(source="WinEventLog:Security" (EventCode="4656" OR EventCode="4663" OR EventCode="4658") (ObjectName="*.AAA" OR ObjectName="*.ZZZ"))
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id IN ["4656", "4663", "4658"] ObjectName IN ["*.AAA", "*.ZZZ"])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*4656|.*4663|.*4658))(?=.*(?:.*.*\.AAA|.*.*\.ZZZ)))'
```



