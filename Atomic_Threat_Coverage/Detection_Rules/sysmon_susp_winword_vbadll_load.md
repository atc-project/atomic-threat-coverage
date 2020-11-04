| Title                    | VBA DLL Loaded Via Microsoft Word       |
|:-------------------------|:------------------|
| **Description**          | Detects DLL's Loaded Via Word Containing VBA Macros |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0001: Initial Access](https://attack.mitre.org/tactics/TA0001)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1193: Spearphishing Attachment](https://attack.mitre.org/techniques/T1193)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0011_7_windows_sysmon_image_loaded](../Data_Needed/DN_0011_7_windows_sysmon_image_loaded.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1193: Spearphishing Attachment](../Triggers/T1193.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Alerts on legitimate macro usage as well, will need to filter as appropriate</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://medium.com/threatpunter/detecting-adversary-tradecraft-with-image-load-event-logging-and-eql-8de93338c16](https://medium.com/threatpunter/detecting-adversary-tradecraft-with-image-load-event-logging-and-eql-8de93338c16)</li></ul>  |
| **Author**               | Antonlovesdnb |


## Detection Rules

### Sigma rule

```
title: VBA DLL Loaded Via Microsoft Word
id: e6ce8457-68b1-485b-9bdd-3c2b5d679aa9
status: experimental
description: Detects DLL's Loaded Via Word Containing VBA Macros
references:
    - https://medium.com/threatpunter/detecting-adversary-tradecraft-with-image-load-event-logging-and-eql-8de93338c16
author: Antonlovesdnb
date: 2020/02/19
tags:
    - attack.initial_access
    - attack.t1193
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 7
        Image:
            - '*\winword.exe*'
            - '*\powerpnt.exe*'
            - '*\excel.exe*'
            - '*\outlook.exe*'
        ImageLoaded:
            - '*\VBE7.DLL*'
            - '*\VBEUI.DLL*'
            - '*\VBE7INTL.DLL*'
    condition: selection
falsepositives:
    - Alerts on legitimate macro usage as well, will need to filter as appropriate
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "7" -and ($_.message -match "Image.*.*\\winword.exe.*" -or $_.message -match "Image.*.*\\powerpnt.exe.*" -or $_.message -match "Image.*.*\\excel.exe.*" -or $_.message -match "Image.*.*\\outlook.exe.*") -and ($_.message -match "ImageLoaded.*.*\\VBE7.DLL.*" -or $_.message -match "ImageLoaded.*.*\\VBEUI.DLL.*" -or $_.message -match "ImageLoaded.*.*\\VBE7INTL.DLL.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND winlog.event_id:"7" AND winlog.event_data.Image.keyword:(*\\winword.exe* OR *\\powerpnt.exe* OR *\\excel.exe* OR *\\outlook.exe*) AND winlog.event_data.ImageLoaded.keyword:(*\\VBE7.DLL* OR *\\VBEUI.DLL* OR *\\VBE7INTL.DLL*))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/e6ce8457-68b1-485b-9bdd-3c2b5d679aa9 <<EOF
{
  "metadata": {
    "title": "VBA DLL Loaded Via Microsoft Word",
    "description": "Detects DLL's Loaded Via Word Containing VBA Macros",
    "tags": [
      "attack.initial_access",
      "attack.t1193"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"7\" AND winlog.event_data.Image.keyword:(*\\\\winword.exe* OR *\\\\powerpnt.exe* OR *\\\\excel.exe* OR *\\\\outlook.exe*) AND winlog.event_data.ImageLoaded.keyword:(*\\\\VBE7.DLL* OR *\\\\VBEUI.DLL* OR *\\\\VBE7INTL.DLL*))"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"7\" AND winlog.event_data.Image.keyword:(*\\\\winword.exe* OR *\\\\powerpnt.exe* OR *\\\\excel.exe* OR *\\\\outlook.exe*) AND winlog.event_data.ImageLoaded.keyword:(*\\\\VBE7.DLL* OR *\\\\VBEUI.DLL* OR *\\\\VBE7INTL.DLL*))",
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
        "subject": "Sigma Rule 'VBA DLL Loaded Via Microsoft Word'",
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
(EventID:"7" AND Image.keyword:(*\\winword.exe* *\\powerpnt.exe* *\\excel.exe* *\\outlook.exe*) AND ImageLoaded.keyword:(*\\VBE7.DLL* *\\VBEUI.DLL* *\\VBE7INTL.DLL*))
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="7" (Image="*\\winword.exe*" OR Image="*\\powerpnt.exe*" OR Image="*\\excel.exe*" OR Image="*\\outlook.exe*") (ImageLoaded="*\\VBE7.DLL*" OR ImageLoaded="*\\VBEUI.DLL*" OR ImageLoaded="*\\VBE7INTL.DLL*"))
```


### logpoint
    
```
(event_id="7" Image IN ["*\\winword.exe*", "*\\powerpnt.exe*", "*\\excel.exe*", "*\\outlook.exe*"] ImageLoaded IN ["*\\VBE7.DLL*", "*\\VBEUI.DLL*", "*\\VBE7INTL.DLL*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*7)(?=.*(?:.*.*\winword\.exe.*|.*.*\powerpnt\.exe.*|.*.*\excel\.exe.*|.*.*\outlook\.exe.*))(?=.*(?:.*.*\VBE7\.DLL.*|.*.*\VBEUI\.DLL.*|.*.*\VBE7INTL\.DLL.*)))'
```



