| Title                    | Windows Mangement Instrumentation DLL Loaded Via Microsoft Word       |
|:-------------------------|:------------------|
| **Description**          | Detects DLL's Loaded Via Word Containing VBA Macros Executing WMI Commands |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1047: Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0011_7_windows_sysmon_image_loaded](../Data_Needed/DN_0011_7_windows_sysmon_image_loaded.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1047: Windows Management Instrumentation](../Triggers/T1047.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Possible. Requires further testing.</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://medium.com/threatpunter/detecting-adversary-tradecraft-with-image-load-event-logging-and-eql-8de93338c16](https://medium.com/threatpunter/detecting-adversary-tradecraft-with-image-load-event-logging-and-eql-8de93338c16)</li><li>[https://www.carbonblack.com/2019/04/24/cb-tau-threat-intelligence-notification-emotet-utilizing-wmi-to-launch-powershell-encoded-code/](https://www.carbonblack.com/2019/04/24/cb-tau-threat-intelligence-notification-emotet-utilizing-wmi-to-launch-powershell-encoded-code/)</li><li>[https://media.cert.europa.eu/static/SecurityAdvisories/2019/CERT-EU-SA2019-021.pdf](https://media.cert.europa.eu/static/SecurityAdvisories/2019/CERT-EU-SA2019-021.pdf)</li></ul>  |
| **Author**               | Michael R. (@nahamike01) |


## Detection Rules

### Sigma rule

```
title: Windows Mangement Instrumentation DLL Loaded Via Microsoft Word
id: a457f232-7df9-491d-898f-b5aabd2cbe2f
status: experimental
description: Detects DLL's Loaded Via Word Containing VBA Macros Executing WMI Commands
references:
    - https://medium.com/threatpunter/detecting-adversary-tradecraft-with-image-load-event-logging-and-eql-8de93338c16
    - https://www.carbonblack.com/2019/04/24/cb-tau-threat-intelligence-notification-emotet-utilizing-wmi-to-launch-powershell-encoded-code/
    - https://media.cert.europa.eu/static/SecurityAdvisories/2019/CERT-EU-SA2019-021.pdf
author: Michael R. (@nahamike01)
date: 2019/12/26
tags:
    - attack.execution
    - attack.t1047
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 7
        Image:
            - '*\winword.exe'
            - '*\powerpnt.exe'
            - '*\excel.exe'
            - '*\outlook.exe'
        ImageLoaded:
            - '*\wmiutils.dll'
            - '*\wbemcomn.dll'
            - '*\wbemprox.dll'
            - '*\wbemdisp.dll'
            - '*\wbemsvc.dll'
    condition: selection
falsepositives:
    - Possible. Requires further testing.
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "7" -and ($_.message -match "Image.*.*\\winword.exe" -or $_.message -match "Image.*.*\\powerpnt.exe" -or $_.message -match "Image.*.*\\excel.exe" -or $_.message -match "Image.*.*\\outlook.exe") -and ($_.message -match "ImageLoaded.*.*\\wmiutils.dll" -or $_.message -match "ImageLoaded.*.*\\wbemcomn.dll" -or $_.message -match "ImageLoaded.*.*\\wbemprox.dll" -or $_.message -match "ImageLoaded.*.*\\wbemdisp.dll" -or $_.message -match "ImageLoaded.*.*\\wbemsvc.dll")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND winlog.event_id:"7" AND winlog.event_data.Image.keyword:(*\\winword.exe OR *\\powerpnt.exe OR *\\excel.exe OR *\\outlook.exe) AND winlog.event_data.ImageLoaded.keyword:(*\\wmiutils.dll OR *\\wbemcomn.dll OR *\\wbemprox.dll OR *\\wbemdisp.dll OR *\\wbemsvc.dll))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/a457f232-7df9-491d-898f-b5aabd2cbe2f <<EOF
{
  "metadata": {
    "title": "Windows Mangement Instrumentation DLL Loaded Via Microsoft Word",
    "description": "Detects DLL's Loaded Via Word Containing VBA Macros Executing WMI Commands",
    "tags": [
      "attack.execution",
      "attack.t1047"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"7\" AND winlog.event_data.Image.keyword:(*\\\\winword.exe OR *\\\\powerpnt.exe OR *\\\\excel.exe OR *\\\\outlook.exe) AND winlog.event_data.ImageLoaded.keyword:(*\\\\wmiutils.dll OR *\\\\wbemcomn.dll OR *\\\\wbemprox.dll OR *\\\\wbemdisp.dll OR *\\\\wbemsvc.dll))"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"7\" AND winlog.event_data.Image.keyword:(*\\\\winword.exe OR *\\\\powerpnt.exe OR *\\\\excel.exe OR *\\\\outlook.exe) AND winlog.event_data.ImageLoaded.keyword:(*\\\\wmiutils.dll OR *\\\\wbemcomn.dll OR *\\\\wbemprox.dll OR *\\\\wbemdisp.dll OR *\\\\wbemsvc.dll))",
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
        "subject": "Sigma Rule 'Windows Mangement Instrumentation DLL Loaded Via Microsoft Word'",
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
(EventID:"7" AND Image.keyword:(*\\winword.exe *\\powerpnt.exe *\\excel.exe *\\outlook.exe) AND ImageLoaded.keyword:(*\\wmiutils.dll *\\wbemcomn.dll *\\wbemprox.dll *\\wbemdisp.dll *\\wbemsvc.dll))
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="7" (Image="*\\winword.exe" OR Image="*\\powerpnt.exe" OR Image="*\\excel.exe" OR Image="*\\outlook.exe") (ImageLoaded="*\\wmiutils.dll" OR ImageLoaded="*\\wbemcomn.dll" OR ImageLoaded="*\\wbemprox.dll" OR ImageLoaded="*\\wbemdisp.dll" OR ImageLoaded="*\\wbemsvc.dll"))
```


### logpoint
    
```
(event_id="7" Image IN ["*\\winword.exe", "*\\powerpnt.exe", "*\\excel.exe", "*\\outlook.exe"] ImageLoaded IN ["*\\wmiutils.dll", "*\\wbemcomn.dll", "*\\wbemprox.dll", "*\\wbemdisp.dll", "*\\wbemsvc.dll"])
```


### grep
    
```
grep -P '^(?:.*(?=.*7)(?=.*(?:.*.*\winword\.exe|.*.*\powerpnt\.exe|.*.*\excel\.exe|.*.*\outlook\.exe))(?=.*(?:.*.*\wmiutils\.dll|.*.*\wbemcomn\.dll|.*.*\wbemprox\.dll|.*.*\wbemdisp\.dll|.*.*\wbemsvc\.dll)))'
```



