| Title                    | Suspicious desktop.ini Action       |
|:-------------------------|:------------------|
| **Description**          | Detects unusual processes accessing desktop.ini, which can be leveraged to alter how Explorer displays a folder's content (i.e. renaming files) without changing them on disk. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1023: Shortcut Modification](https://attack.mitre.org/techniques/T1023)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0015_11_windows_sysmon_FileCreate](../Data_Needed/DN_0015_11_windows_sysmon_FileCreate.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1023: Shortcut Modification](../Triggers/T1023.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Operations performed through Windows SCCM or equivalent</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://isc.sans.edu/forums/diary/Desktopini+as+a+postexploitation+tool/25912/](https://isc.sans.edu/forums/diary/Desktopini+as+a+postexploitation+tool/25912/)</li></ul>  |
| **Author**               | Maxime Thiebaut (@0xThiebaut) |


## Detection Rules

### Sigma rule

```
title: Suspicious desktop.ini Action
id: 81315b50-6b60-4d8f-9928-3466e1022515
status: experimental
description: Detects unusual processes accessing desktop.ini, which can be leveraged to alter how Explorer displays a folder's content (i.e. renaming files) without changing them on disk.
references:
    - https://isc.sans.edu/forums/diary/Desktopini+as+a+postexploitation+tool/25912/
author: Maxime Thiebaut (@0xThiebaut)
date: 2020/03/19
tags:
    - attack.persistence
    - attack.t1023
logsource:
    product: windows
    service: sysmon
detection:
    filter:
        Image:
            - 'C:\Windows\explorer.exe'
            - 'C:\Windows\System32\msiexec.exe'
            - 'C:\Windows\System32\mmc.exe'
    selection:
        EventID: 11
        TargetFilename|endswith: '\desktop.ini'
    condition: selection and not filter
falsepositives:
    - Operations performed through Windows SCCM or equivalent
level: medium

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "11" -and $_.message -match "TargetFilename.*.*\\desktop.ini") -and  -not (($_.message -match "C:\\Windows\\explorer.exe" -or $_.message -match "C:\\Windows\\System32\\msiexec.exe" -or $_.message -match "C:\\Windows\\System32\\mmc.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND (winlog.event_id:"11" AND winlog.event_data.TargetFilename.keyword:*\\desktop.ini) AND (NOT (winlog.event_data.Image:("C\:\\Windows\\explorer.exe" OR "C\:\\Windows\\System32\\msiexec.exe" OR "C\:\\Windows\\System32\\mmc.exe"))))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/81315b50-6b60-4d8f-9928-3466e1022515 <<EOF
{
  "metadata": {
    "title": "Suspicious desktop.ini Action",
    "description": "Detects unusual processes accessing desktop.ini, which can be leveraged to alter how Explorer displays a folder's content (i.e. renaming files) without changing them on disk.",
    "tags": [
      "attack.persistence",
      "attack.t1023"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND (winlog.event_id:\"11\" AND winlog.event_data.TargetFilename.keyword:*\\\\desktop.ini) AND (NOT (winlog.event_data.Image:(\"C\\:\\\\Windows\\\\explorer.exe\" OR \"C\\:\\\\Windows\\\\System32\\\\msiexec.exe\" OR \"C\\:\\\\Windows\\\\System32\\\\mmc.exe\"))))"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND (winlog.event_id:\"11\" AND winlog.event_data.TargetFilename.keyword:*\\\\desktop.ini) AND (NOT (winlog.event_data.Image:(\"C\\:\\\\Windows\\\\explorer.exe\" OR \"C\\:\\\\Windows\\\\System32\\\\msiexec.exe\" OR \"C\\:\\\\Windows\\\\System32\\\\mmc.exe\"))))",
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
        "subject": "Sigma Rule 'Suspicious desktop.ini Action'",
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
((EventID:"11" AND TargetFilename.keyword:*\\desktop.ini) AND (NOT (Image:("C\:\\Windows\\explorer.exe" "C\:\\Windows\\System32\\msiexec.exe" "C\:\\Windows\\System32\\mmc.exe"))))
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode="11" TargetFilename="*\\desktop.ini") NOT ((Image="C:\\Windows\\explorer.exe" OR Image="C:\\Windows\\System32\\msiexec.exe" OR Image="C:\\Windows\\System32\\mmc.exe")))
```


### logpoint
    
```
((event_id="11" TargetFilename="*\\desktop.ini")  -(Image IN ["C:\\Windows\\explorer.exe", "C:\\Windows\\System32\\msiexec.exe", "C:\\Windows\\System32\\mmc.exe"]))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*11)(?=.*.*\desktop\.ini)))(?=.*(?!.*(?:.*(?=.*(?:.*C:\Windows\explorer\.exe|.*C:\Windows\System32\msiexec\.exe|.*C:\Windows\System32\mmc\.exe))))))'
```



