| Title                    | Active Directory Kerberos DLL Loaded Via Office Applications       |
|:-------------------------|:------------------|
| **Description**          | Detects Kerberos DLL being loaded by an Office Product |
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
title: Active Directory Kerberos DLL Loaded Via Office Applications
id: 7417e29e-c2e7-4cf6-a2e8-767228c64837
status: experimental
description: Detects Kerberos DLL being loaded by an Office Product
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
            - '*\kerberos.dll*'
    condition: selection
falsepositives:
    - Alerts on legitimate macro usage as well, will need to filter as appropriate
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "7" -and ($_.message -match "Image.*.*\\winword.exe.*" -or $_.message -match "Image.*.*\\powerpnt.exe.*" -or $_.message -match "Image.*.*\\excel.exe.*" -or $_.message -match "Image.*.*\\outlook.exe.*") -and ($_.message -match "ImageLoaded.*.*\\kerberos.dll.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND winlog.event_id:"7" AND winlog.event_data.Image.keyword:(*\\winword.exe* OR *\\powerpnt.exe* OR *\\excel.exe* OR *\\outlook.exe*) AND winlog.event_data.ImageLoaded.keyword:(*\\kerberos.dll*))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/7417e29e-c2e7-4cf6-a2e8-767228c64837 <<EOF
{
  "metadata": {
    "title": "Active Directory Kerberos DLL Loaded Via Office Applications",
    "description": "Detects Kerberos DLL being loaded by an Office Product",
    "tags": [
      "attack.initial_access",
      "attack.t1193"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"7\" AND winlog.event_data.Image.keyword:(*\\\\winword.exe* OR *\\\\powerpnt.exe* OR *\\\\excel.exe* OR *\\\\outlook.exe*) AND winlog.event_data.ImageLoaded.keyword:(*\\\\kerberos.dll*))"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"7\" AND winlog.event_data.Image.keyword:(*\\\\winword.exe* OR *\\\\powerpnt.exe* OR *\\\\excel.exe* OR *\\\\outlook.exe*) AND winlog.event_data.ImageLoaded.keyword:(*\\\\kerberos.dll*))",
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
        "subject": "Sigma Rule 'Active Directory Kerberos DLL Loaded Via Office Applications'",
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
(EventID:"7" AND Image.keyword:(*\\winword.exe* *\\powerpnt.exe* *\\excel.exe* *\\outlook.exe*) AND ImageLoaded.keyword:(*\\kerberos.dll*))
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="7" (Image="*\\winword.exe*" OR Image="*\\powerpnt.exe*" OR Image="*\\excel.exe*" OR Image="*\\outlook.exe*") (ImageLoaded="*\\kerberos.dll*"))
```


### logpoint
    
```
(event_id="7" Image IN ["*\\winword.exe*", "*\\powerpnt.exe*", "*\\excel.exe*", "*\\outlook.exe*"] ImageLoaded IN ["*\\kerberos.dll*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*7)(?=.*(?:.*.*\winword\.exe.*|.*.*\powerpnt\.exe.*|.*.*\excel\.exe.*|.*.*\outlook\.exe.*))(?=.*(?:.*.*\kerberos\.dll.*)))'
```



