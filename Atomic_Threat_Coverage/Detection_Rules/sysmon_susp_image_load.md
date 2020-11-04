| Title                    | Possible Process Hollowing Image Loading       |
|:-------------------------|:------------------|
| **Description**          | Detects Loading of samlib.dll, WinSCard.dll from untypical process e.g. through process hollowing by Mimikatz |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1073: DLL Side-Loading](https://attack.mitre.org/techniques/T1073)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0011_7_windows_sysmon_image_loaded](../Data_Needed/DN_0011_7_windows_sysmon_image_loaded.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1073: DLL Side-Loading](../Triggers/T1073.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Very likely, needs more tuning</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for.html](https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for.html)</li></ul>  |
| **Author**               | Markus Neis |


## Detection Rules

### Sigma rule

```
title: Possible Process Hollowing Image Loading
id: e32ce4f5-46c6-4c47-ba69-5de3c9193cd7
status: experimental
description: Detects Loading of samlib.dll, WinSCard.dll from untypical process e.g. through process hollowing by Mimikatz
references:
    - https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for.html
author: Markus Neis
date: 2018/01/07
tags:
    - attack.defense_evasion
    - attack.t1073
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 7
        Image:
            - '*\notepad.exe'
        ImageLoaded:
            - '*\samlib.dll'
            - '*\WinSCard.dll'
    condition: selection
falsepositives:
    - Very likely, needs more tuning
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "7" -and ($_.message -match "Image.*.*\\notepad.exe") -and ($_.message -match "ImageLoaded.*.*\\samlib.dll" -or $_.message -match "ImageLoaded.*.*\\WinSCard.dll")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND winlog.event_id:"7" AND winlog.event_data.Image.keyword:(*\\notepad.exe) AND winlog.event_data.ImageLoaded.keyword:(*\\samlib.dll OR *\\WinSCard.dll))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/e32ce4f5-46c6-4c47-ba69-5de3c9193cd7 <<EOF
{
  "metadata": {
    "title": "Possible Process Hollowing Image Loading",
    "description": "Detects Loading of samlib.dll, WinSCard.dll from untypical process e.g. through process hollowing by Mimikatz",
    "tags": [
      "attack.defense_evasion",
      "attack.t1073"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"7\" AND winlog.event_data.Image.keyword:(*\\\\notepad.exe) AND winlog.event_data.ImageLoaded.keyword:(*\\\\samlib.dll OR *\\\\WinSCard.dll))"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"7\" AND winlog.event_data.Image.keyword:(*\\\\notepad.exe) AND winlog.event_data.ImageLoaded.keyword:(*\\\\samlib.dll OR *\\\\WinSCard.dll))",
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
        "subject": "Sigma Rule 'Possible Process Hollowing Image Loading'",
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
(EventID:"7" AND Image.keyword:(*\\notepad.exe) AND ImageLoaded.keyword:(*\\samlib.dll *\\WinSCard.dll))
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="7" (Image="*\\notepad.exe") (ImageLoaded="*\\samlib.dll" OR ImageLoaded="*\\WinSCard.dll"))
```


### logpoint
    
```
(event_id="7" Image IN ["*\\notepad.exe"] ImageLoaded IN ["*\\samlib.dll", "*\\WinSCard.dll"])
```


### grep
    
```
grep -P '^(?:.*(?=.*7)(?=.*(?:.*.*\notepad\.exe))(?=.*(?:.*.*\samlib\.dll|.*.*\WinSCard\.dll)))'
```



