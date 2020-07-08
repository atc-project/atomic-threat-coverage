| Title                    | Suspicious Parent of Csc.exe       |
|:-------------------------|:------------------|
| **Description**          | Detects a suspicious parent of csc.exe, which could by a sign of payload delivery |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1036: Masquerading](https://attack.mitre.org/techniques/T1036)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unkown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://twitter.com/SBousseaden/status/1094924091256176641](https://twitter.com/SBousseaden/status/1094924091256176641)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Suspicious Parent of Csc.exe
id: b730a276-6b63-41b8-bcf8-55930c8fc6ee
description: Detects a suspicious parent of csc.exe, which could by a sign of payload delivery
status: experimental
references:
    - https://twitter.com/SBousseaden/status/1094924091256176641
author: Florian Roth
date: 2019/02/11
tags:
    - attack.defense_evasion
    - attack.t1036
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: '*\csc.exe*'
        ParentImage:
            - '*\wscript.exe'
            - '*\cscript.exe'
            - '*\mshta.exe'
    condition: selection
falsepositives:
    - Unkown
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\\csc.exe.*" -and ($_.message -match "ParentImage.*.*\\wscript.exe" -or $_.message -match "ParentImage.*.*\\cscript.exe" -or $_.message -match "ParentImage.*.*\\mshta.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:*\\csc.exe* AND winlog.event_data.ParentImage.keyword:(*\\wscript.exe OR *\\cscript.exe OR *\\mshta.exe))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/b730a276-6b63-41b8-bcf8-55930c8fc6ee <<EOF
{
  "metadata": {
    "title": "Suspicious Parent of Csc.exe",
    "description": "Detects a suspicious parent of csc.exe, which could by a sign of payload delivery",
    "tags": [
      "attack.defense_evasion",
      "attack.t1036"
    ],
    "query": "(winlog.event_data.Image.keyword:*\\\\csc.exe* AND winlog.event_data.ParentImage.keyword:(*\\\\wscript.exe OR *\\\\cscript.exe OR *\\\\mshta.exe))"
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
                    "query": "(winlog.event_data.Image.keyword:*\\\\csc.exe* AND winlog.event_data.ParentImage.keyword:(*\\\\wscript.exe OR *\\\\cscript.exe OR *\\\\mshta.exe))",
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
        "subject": "Sigma Rule 'Suspicious Parent of Csc.exe'",
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
(Image.keyword:*\\csc.exe* AND ParentImage.keyword:(*\\wscript.exe *\\cscript.exe *\\mshta.exe))
```


### splunk
    
```
(Image="*\\csc.exe*" (ParentImage="*\\wscript.exe" OR ParentImage="*\\cscript.exe" OR ParentImage="*\\mshta.exe"))
```


### logpoint
    
```
(event_id="1" Image="*\\csc.exe*" ParentImage IN ["*\\wscript.exe", "*\\cscript.exe", "*\\mshta.exe"])
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\csc\.exe.*)(?=.*(?:.*.*\wscript\.exe|.*.*\cscript\.exe|.*.*\mshta\.exe)))'
```



