| Title                    | In-memory PowerShell       |
|:-------------------------|:------------------|
| **Description**          | Detects loading of essential DLL used by PowerShell, but not by the process powershell.exe. Detects meterpreter's "load powershell" extension. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0011_7_windows_sysmon_image_loaded](../Data_Needed/DN_0011_7_windows_sysmon_image_loaded.md)</li></ul>  |
| **Enrichment** |<ul><li>[EN_0001_cache_sysmon_event_id_1_info](../Enrichments/EN_0001_cache_sysmon_event_id_1_info.md)</li><li>[EN_0003_enrich_other_sysmon_events_with_event_id_1_data](../Enrichments/EN_0003_enrich_other_sysmon_events_with_event_id_1_data.md)</li></ul> |
| **Trigger**              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Used by some .NET binaries, minimal on user workstation.</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://adsecurity.org/?p=2921](https://adsecurity.org/?p=2921)</li><li>[https://github.com/p3nt4/PowerShdll](https://github.com/p3nt4/PowerShdll)</li></ul>  |
| **Author**               | Tom Kern, oscd.community |


## Detection Rules

### Sigma rule

```
title: In-memory PowerShell
id: 092bc4b9-3d1d-43b4-a6b4-8c8acd83522f
status: experimental
description: Detects loading of essential DLL used by PowerShell, but not by the process powershell.exe. Detects meterpreter's "load powershell" extension.
author: Tom Kern, oscd.community
date: 2019/11/14
modified: 2019/11/30
references:
    - https://adsecurity.org/?p=2921
    - https://github.com/p3nt4/PowerShdll
tags:
    - attack.t1086
    - attack.execution
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 7
        ImageLoaded|endswith:
            - '\System.Management.Automation.Dll'
            - '\System.Management.Automation.ni.Dll'
    filter:
        Image|endswith:
            - '\powershell.exe'
            - '\WINDOWS\System32\sdiagnhost.exe'
        User: 'NT AUTHORITY\SYSTEM'
    condition: selection and not filter
falsepositives:
    - Used by some .NET binaries, minimal on user workstation.
level: high
enrichment:
    - EN_0001_cache_sysmon_event_id_1_info                      # http://bit.ly/314zc6x
    - EN_0003_enrich_other_sysmon_events_with_event_id_1_data   # http://bit.ly/2ojW7fw

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "7" -and ($_.message -match "ImageLoaded.*.*\\System.Management.Automation.Dll" -or $_.message -match "ImageLoaded.*.*\\System.Management.Automation.ni.Dll")) -and  -not (($_.message -match "Image.*.*\\powershell.exe" -or $_.message -match "Image.*.*\\WINDOWS\\System32\\sdiagnhost.exe") -and $_.message -match "User.*NT AUTHORITY\\SYSTEM")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND (winlog.event_id:"7" AND winlog.event_data.ImageLoaded.keyword:(*\\System.Management.Automation.Dll OR *\\System.Management.Automation.ni.Dll)) AND (NOT (winlog.event_data.Image.keyword:(*\\powershell.exe OR *\\WINDOWS\\System32\\sdiagnhost.exe) AND winlog.event_data.User:"NT\ AUTHORITY\\SYSTEM")))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/092bc4b9-3d1d-43b4-a6b4-8c8acd83522f <<EOF
{
  "metadata": {
    "title": "In-memory PowerShell",
    "description": "Detects loading of essential DLL used by PowerShell, but not by the process powershell.exe. Detects meterpreter's \"load powershell\" extension.",
    "tags": [
      "attack.t1086",
      "attack.execution"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND (winlog.event_id:\"7\" AND winlog.event_data.ImageLoaded.keyword:(*\\\\System.Management.Automation.Dll OR *\\\\System.Management.Automation.ni.Dll)) AND (NOT (winlog.event_data.Image.keyword:(*\\\\powershell.exe OR *\\\\WINDOWS\\\\System32\\\\sdiagnhost.exe) AND winlog.event_data.User:\"NT\\ AUTHORITY\\\\SYSTEM\")))"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND (winlog.event_id:\"7\" AND winlog.event_data.ImageLoaded.keyword:(*\\\\System.Management.Automation.Dll OR *\\\\System.Management.Automation.ni.Dll)) AND (NOT (winlog.event_data.Image.keyword:(*\\\\powershell.exe OR *\\\\WINDOWS\\\\System32\\\\sdiagnhost.exe) AND winlog.event_data.User:\"NT\\ AUTHORITY\\\\SYSTEM\")))",
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
        "subject": "Sigma Rule 'In-memory PowerShell'",
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
((EventID:"7" AND ImageLoaded.keyword:(*\\System.Management.Automation.Dll *\\System.Management.Automation.ni.Dll)) AND (NOT (Image.keyword:(*\\powershell.exe *\\WINDOWS\\System32\\sdiagnhost.exe) AND User:"NT AUTHORITY\\SYSTEM")))
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode="7" (ImageLoaded="*\\System.Management.Automation.Dll" OR ImageLoaded="*\\System.Management.Automation.ni.Dll")) NOT ((Image="*\\powershell.exe" OR Image="*\\WINDOWS\\System32\\sdiagnhost.exe") User="NT AUTHORITY\\SYSTEM"))
```


### logpoint
    
```
((event_id="7" ImageLoaded IN ["*\\System.Management.Automation.Dll", "*\\System.Management.Automation.ni.Dll"])  -(Image IN ["*\\powershell.exe", "*\\WINDOWS\\System32\\sdiagnhost.exe"] User="NT AUTHORITY\\SYSTEM"))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*7)(?=.*(?:.*.*\System\.Management\.Automation\.Dll|.*.*\System\.Management\.Automation\.ni\.Dll))))(?=.*(?!.*(?:.*(?=.*(?:.*.*\powershell\.exe|.*.*\WINDOWS\System32\sdiagnhost\.exe))(?=.*NT AUTHORITY\SYSTEM)))))'
```



