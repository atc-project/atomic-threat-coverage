| Title                    | QuarksPwDump Dump File       |
|:-------------------------|:------------------|
| **Description**          | Detects a dump file written by QuarksPwDump password dumper |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1003: OS Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0015_11_windows_sysmon_FileCreate](../Data_Needed/DN_0015_11_windows_sysmon_FileCreate.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1003: OS Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://jpcertcc.github.io/ToolAnalysisResultSheet/details/QuarksPWDump.htm](https://jpcertcc.github.io/ToolAnalysisResultSheet/details/QuarksPWDump.htm)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: QuarksPwDump Dump File
id: 847def9e-924d-4e90-b7c4-5f581395a2b4
status: experimental
description: Detects a dump file written by QuarksPwDump password dumper
references:
    - https://jpcertcc.github.io/ToolAnalysisResultSheet/details/QuarksPWDump.htm
author: Florian Roth
date: 2018/02/10
tags:
  - attack.credential_access
  - attack.t1003
level: critical
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        # Sysmon: File Creation (ID 11)
        EventID: 11
        TargetFilename: '*\AppData\Local\Temp\SAM-*.dmp*'
    condition: selection
falsepositives:
    - Unknown


```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "11" -and $_.message -match "TargetFilename.*.*\\AppData\\Local\\Temp\\SAM-.*.dmp.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND winlog.event_id:"11" AND winlog.event_data.TargetFilename.keyword:*\\AppData\\Local\\Temp\\SAM\-*.dmp*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/847def9e-924d-4e90-b7c4-5f581395a2b4 <<EOF
{
  "metadata": {
    "title": "QuarksPwDump Dump File",
    "description": "Detects a dump file written by QuarksPwDump password dumper",
    "tags": [
      "attack.credential_access",
      "attack.t1003"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"11\" AND winlog.event_data.TargetFilename.keyword:*\\\\AppData\\\\Local\\\\Temp\\\\SAM\\-*.dmp*)"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"11\" AND winlog.event_data.TargetFilename.keyword:*\\\\AppData\\\\Local\\\\Temp\\\\SAM\\-*.dmp*)",
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
        "subject": "Sigma Rule 'QuarksPwDump Dump File'",
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
(EventID:"11" AND TargetFilename.keyword:*\\AppData\\Local\\Temp\\SAM\-*.dmp*)
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="11" TargetFilename="*\\AppData\\Local\\Temp\\SAM-*.dmp*")
```


### logpoint
    
```
(event_id="11" TargetFilename="*\\AppData\\Local\\Temp\\SAM-*.dmp*")
```


### grep
    
```
grep -P '^(?:.*(?=.*11)(?=.*.*\AppData\Local\Temp\SAM-.*\.dmp.*))'
```



