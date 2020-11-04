| Title                    | Invocation of Active Directory Diagnostic Tool (ntdsutil.exe)       |
|:-------------------------|:------------------|
| **Description**          | Detects execution of ntdsutil.exe, which can be used for various attacks against the NTDS database (NTDS.DIT) |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1003: OS Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1003: OS Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>NTDS maintenance</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://jpcertcc.github.io/ToolAnalysisResultSheet/details/ntdsutil.htm](https://jpcertcc.github.io/ToolAnalysisResultSheet/details/ntdsutil.htm)</li></ul>  |
| **Author**               | Thomas Patzke |


## Detection Rules

### Sigma rule

```
title: Invocation of Active Directory Diagnostic Tool (ntdsutil.exe)
id: 2afafd61-6aae-4df4-baed-139fa1f4c345
description: Detects execution of ntdsutil.exe, which can be used for various attacks against the NTDS database (NTDS.DIT)
status: experimental
references:
    - https://jpcertcc.github.io/ToolAnalysisResultSheet/details/ntdsutil.htm
author: Thomas Patzke
date: 2019/01/16
tags:
    - attack.credential_access
    - attack.t1003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine: '*\ntdsutil*'
    condition: selection
falsepositives:
    - NTDS maintenance
level: high

```





### powershell
    
```
Get-WinEvent | where {$_.message -match "CommandLine.*.*\\ntdsutil.*" } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.CommandLine.keyword:*\\ntdsutil*
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/2afafd61-6aae-4df4-baed-139fa1f4c345 <<EOF
{
  "metadata": {
    "title": "Invocation of Active Directory Diagnostic Tool (ntdsutil.exe)",
    "description": "Detects execution of ntdsutil.exe, which can be used for various attacks against the NTDS database (NTDS.DIT)",
    "tags": [
      "attack.credential_access",
      "attack.t1003"
    ],
    "query": "winlog.event_data.CommandLine.keyword:*\\\\ntdsutil*"
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
                    "query": "winlog.event_data.CommandLine.keyword:*\\\\ntdsutil*",
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
        "subject": "Sigma Rule 'Invocation of Active Directory Diagnostic Tool (ntdsutil.exe)'",
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
CommandLine.keyword:*\\ntdsutil*
```


### splunk
    
```
CommandLine="*\\ntdsutil*"
```


### logpoint
    
```
CommandLine="*\\ntdsutil*"
```


### grep
    
```
grep -P '^.*\ntdsutil.*'
```



