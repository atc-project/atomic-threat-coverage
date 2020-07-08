| Title                    | DIT Snapshot Viewer Use       |
|:-------------------------|:------------------|
| **Description**          | Detects the use of Ditsnap tool. Seems to be a tool for ransomware groups. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1003: OS Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1003: OS Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Legitimate admin usage</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://thedfirreport.com/2020/06/21/snatch-ransomware/](https://thedfirreport.com/2020/06/21/snatch-ransomware/)</li><li>[https://github.com/yosqueoy/ditsnap](https://github.com/yosqueoy/ditsnap)</li></ul>  |
| **Author**               | Furkan Caliskan (@caliskanfurkan_) |


## Detection Rules

### Sigma rule

```
title: DIT Snapshot Viewer Use
id: d3b70aad-097e-409c-9df2-450f80dc476b
status: experimental
description: Detects the use of Ditsnap tool. Seems to be a tool for ransomware groups.
references:
    - https://thedfirreport.com/2020/06/21/snatch-ransomware/
    - https://github.com/yosqueoy/ditsnap
author: 'Furkan Caliskan (@caliskanfurkan_)'
date: 2020/07/04
tags:
    - attack.credential_access
    - attack.t1003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\ditsnap.exe'
    selection2:
        CommandLine|contains:
            - 'ditsnap.exe'
    condition: selection or selection2
falsepositives:
    - Legitimate admin usage
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "Image.*.*\\ditsnap.exe") -or ($_.message -match "CommandLine.*.*ditsnap.exe.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:(*\\ditsnap.exe) OR winlog.event_data.CommandLine.keyword:(*ditsnap.exe*))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/d3b70aad-097e-409c-9df2-450f80dc476b <<EOF
{
  "metadata": {
    "title": "DIT Snapshot Viewer Use",
    "description": "Detects the use of Ditsnap tool. Seems to be a tool for ransomware groups.",
    "tags": [
      "attack.credential_access",
      "attack.t1003"
    ],
    "query": "(winlog.event_data.Image.keyword:(*\\\\ditsnap.exe) OR winlog.event_data.CommandLine.keyword:(*ditsnap.exe*))"
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
                    "query": "(winlog.event_data.Image.keyword:(*\\\\ditsnap.exe) OR winlog.event_data.CommandLine.keyword:(*ditsnap.exe*))",
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
        "subject": "Sigma Rule 'DIT Snapshot Viewer Use'",
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
(Image.keyword:(*\\ditsnap.exe) OR CommandLine.keyword:(*ditsnap.exe*))
```


### splunk
    
```
((Image="*\\ditsnap.exe") OR (CommandLine="*ditsnap.exe*"))
```


### logpoint
    
```
(event_id="1" (Image IN ["*\\ditsnap.exe"] OR CommandLine IN ["*ditsnap.exe*"]))
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*.*\ditsnap\.exe)|.*(?:.*.*ditsnap\.exe.*)))'
```



