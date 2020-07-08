| Title                    | Shadow Copies Access via Symlink       |
|:-------------------------|:------------------|
| **Description**          | Shadow Copies storage symbolic link creation using operating systems utilities |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1003: OS Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1003: OS Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Legitimate administrator working with shadow copies, access for backup purposes</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment](https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment)</li></ul>  |
| **Author**               | Teymur Kheirkhabarov, oscd.community |
| Other Tags           | <ul><li>attack.t1003.002</li><li>attack.t1003.003</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Shadow Copies Access via Symlink
id: 40b19fa6-d835-400c-b301-41f3a2baacaf
description: Shadow Copies storage symbolic link creation using operating systems utilities
author: Teymur Kheirkhabarov, oscd.community
date: 2019/10/22
references:
    - https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment
tags:
    - attack.credential_access
    - attack.t1003
    - attack.t1003.002
    - attack.t1003.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - mklink
            - HarddiskVolumeShadowCopy
    condition: selection
falsepositives:
    - Legitimate administrator working with shadow copies, access for backup purposes
status: experimental
level: medium

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "CommandLine.*.*mklink.*" -and $_.message -match "CommandLine.*.*HarddiskVolumeShadowCopy.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.CommandLine.keyword:*mklink* AND winlog.event_data.CommandLine.keyword:*HarddiskVolumeShadowCopy*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/40b19fa6-d835-400c-b301-41f3a2baacaf <<EOF
{
  "metadata": {
    "title": "Shadow Copies Access via Symlink",
    "description": "Shadow Copies storage symbolic link creation using operating systems utilities",
    "tags": [
      "attack.credential_access",
      "attack.t1003",
      "attack.t1003.002",
      "attack.t1003.003"
    ],
    "query": "(winlog.event_data.CommandLine.keyword:*mklink* AND winlog.event_data.CommandLine.keyword:*HarddiskVolumeShadowCopy*)"
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
                    "query": "(winlog.event_data.CommandLine.keyword:*mklink* AND winlog.event_data.CommandLine.keyword:*HarddiskVolumeShadowCopy*)",
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
        "subject": "Sigma Rule 'Shadow Copies Access via Symlink'",
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
(CommandLine.keyword:*mklink* AND CommandLine.keyword:*HarddiskVolumeShadowCopy*)
```


### splunk
    
```
(CommandLine="*mklink*" CommandLine="*HarddiskVolumeShadowCopy*")
```


### logpoint
    
```
(event_id="1" CommandLine="*mklink*" CommandLine="*HarddiskVolumeShadowCopy*")
```


### grep
    
```
grep -P '^(?:.*(?=.*.*mklink.*)(?=.*.*HarddiskVolumeShadowCopy.*))'
```



