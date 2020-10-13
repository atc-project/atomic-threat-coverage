| Title                    | Suspicious Svchost Process       |
|:-------------------------|:------------------|
| **Description**          | Detects a suspicious svchost process start |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1036.005: Match Legitimate Name or Location](https://attack.mitre.org/techniques/T1036/005)</li><li>[T1036: Masquerading](https://attack.mitre.org/techniques/T1036)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Suspicious Svchost Process
id: 01d2e2a1-5f09-44f7-9fc1-24faa7479b6d
status: experimental
description: Detects a suspicious svchost process start
tags:
    - attack.defense_evasion
    - attack.t1036.005
    - attack.t1036      # an old one
author: Florian Roth
date: 2017/08/15
modified: 2020/08/28
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: '*\svchost.exe'
    filter:
        ParentImage:
            - '*\services.exe'
            - '*\MsMpEng.exe'
            - '*\Mrt.exe'
            - '*\rpcnet.exe'
            - '*\svchost.exe'
    filter_null:
        ParentImage: null
    condition: selection and not filter and not filter_null
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Unknown
level: high

```





### powershell
    
```
Get-WinEvent | where {(($_.message -match "Image.*.*\\svchost.exe" -and  -not (($_.message -match "ParentImage.*.*\\services.exe" -or $_.message -match "ParentImage.*.*\\MsMpEng.exe" -or $_.message -match "ParentImage.*.*\\Mrt.exe" -or $_.message -match "ParentImage.*.*\\rpcnet.exe" -or $_.message -match "ParentImage.*.*\\svchost.exe"))) -and  -not (-not ParentImage="*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
((winlog.event_data.Image.keyword:*\\svchost.exe AND (NOT (winlog.event_data.ParentImage.keyword:(*\\services.exe OR *\\MsMpEng.exe OR *\\Mrt.exe OR *\\rpcnet.exe OR *\\svchost.exe)))) AND (NOT (NOT _exists_:winlog.event_data.ParentImage)))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/01d2e2a1-5f09-44f7-9fc1-24faa7479b6d <<EOF
{
  "metadata": {
    "title": "Suspicious Svchost Process",
    "description": "Detects a suspicious svchost process start",
    "tags": [
      "attack.defense_evasion",
      "attack.t1036.005",
      "attack.t1036"
    ],
    "query": "((winlog.event_data.Image.keyword:*\\\\svchost.exe AND (NOT (winlog.event_data.ParentImage.keyword:(*\\\\services.exe OR *\\\\MsMpEng.exe OR *\\\\Mrt.exe OR *\\\\rpcnet.exe OR *\\\\svchost.exe)))) AND (NOT (NOT _exists_:winlog.event_data.ParentImage)))"
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
                    "query": "((winlog.event_data.Image.keyword:*\\\\svchost.exe AND (NOT (winlog.event_data.ParentImage.keyword:(*\\\\services.exe OR *\\\\MsMpEng.exe OR *\\\\Mrt.exe OR *\\\\rpcnet.exe OR *\\\\svchost.exe)))) AND (NOT (NOT _exists_:winlog.event_data.ParentImage)))",
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
        "subject": "Sigma Rule 'Suspicious Svchost Process'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\n      CommandLine = {{_source.CommandLine}}\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
((Image.keyword:*\\svchost.exe AND (NOT (ParentImage.keyword:(*\\services.exe *\\MsMpEng.exe *\\Mrt.exe *\\rpcnet.exe *\\svchost.exe)))) AND (NOT (NOT _exists_:ParentImage)))
```


### splunk
    
```
((Image="*\\svchost.exe" NOT ((ParentImage="*\\services.exe" OR ParentImage="*\\MsMpEng.exe" OR ParentImage="*\\Mrt.exe" OR ParentImage="*\\rpcnet.exe" OR ParentImage="*\\svchost.exe"))) NOT (NOT ParentImage="*")) | table CommandLine,ParentCommandLine
```


### logpoint
    
```
((Image="*\\svchost.exe"  -(ParentImage IN ["*\\services.exe", "*\\MsMpEng.exe", "*\\Mrt.exe", "*\\rpcnet.exe", "*\\svchost.exe"]))  -(-ParentImage=*))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*.*\svchost\.exe)(?=.*(?!.*(?:.*(?=.*(?:.*.*\services\.exe|.*.*\MsMpEng\.exe|.*.*\Mrt\.exe|.*.*\rpcnet\.exe|.*.*\svchost\.exe)))))))(?=.*(?!.*(?:.*(?=.*(?!ParentImage))))))'
```



