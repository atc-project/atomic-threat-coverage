| Title                    | Windows Registry Persistence COM Search Order Hijacking       |
|:-------------------------|:------------------|
| **Description**          | Detects potential COM object hijacking leveraging the COM Search Order |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1038: DLL Search Order Hijacking](https://attack.mitre.org/techniques/T1038)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1038: DLL Search Order Hijacking](../Triggers/T1038.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Some installed utilities (i.e. OneDrive) may serve new COM objects at user-level</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.cyberbit.com/blog/endpoint-security/com-hijacking-windows-overlooked-security-vulnerability/](https://www.cyberbit.com/blog/endpoint-security/com-hijacking-windows-overlooked-security-vulnerability/)</li></ul>  |
| **Author**               | Maxime Thiebaut (@0xThiebaut) |


## Detection Rules

### Sigma rule

```
title: Windows Registry Persistence COM Search Order Hijacking
id: a0ff33d8-79e4-4cef-b4f3-9dc4133ccd12
status: experimental
description: Detects potential COM object hijacking leveraging the COM Search Order
references:
    - https://www.cyberbit.com/blog/endpoint-security/com-hijacking-windows-overlooked-security-vulnerability/
author: Maxime Thiebaut (@0xThiebaut)
date: 2020/04/14
tags:
    - attack.persistence
    - attack.t1038
logsource:
    product: windows
    service: sysmon
detection:
    selection: # Detect new COM servers in the user hive
        EventID: 13
        TargetObject: 'HKU\\*_Classes\CLSID\\*\InProcServer32\(Default)'
    filter:
        Details: # Exclude privileged directories and observed FPs
            - '%%systemroot%%\system32\\*'
            - '%%systemroot%%\SysWow64\\*'
            - '*\AppData\Local\Microsoft\OneDrive\\*\FileCoAuthLib64.dll'
            - '*\AppData\Local\Microsoft\OneDrive\\*\FileSyncShell64.dll'
            - '*\AppData\Local\Microsoft\TeamsMeetingAddin\\*\Microsoft.Teams.AddinLoader.dll'
    condition: selection and not filter
falsepositives:
    - Some installed utilities (i.e. OneDrive) may serve new COM objects at user-level
level: medium

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "13" -and $_.message -match "TargetObject.*HKU\\.*_Classes\\CLSID\\.*\\InProcServer32\\(Default)") -and  -not (($_.message -match "Details.*%%systemroot%%\\system32\\.*" -or $_.message -match "Details.*%%systemroot%%\\SysWow64\\.*" -or $_.message -match "Details.*.*\\AppData\\Local\\Microsoft\\OneDrive\\.*\\FileCoAuthLib64.dll" -or $_.message -match "Details.*.*\\AppData\\Local\\Microsoft\\OneDrive\\.*\\FileSyncShell64.dll" -or $_.message -match "Details.*.*\\AppData\\Local\\Microsoft\\TeamsMeetingAddin\\.*\\Microsoft.Teams.AddinLoader.dll"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND (winlog.event_id:"13" AND winlog.event_data.TargetObject.keyword:HKU\\*_Classes\\CLSID\\*\\InProcServer32\\\(Default\)) AND (NOT (winlog.event_data.Details.keyword:(%%systemroot%%\\system32\\* OR %%systemroot%%\\SysWow64\\* OR *\\AppData\\Local\\Microsoft\\OneDrive\\*\\FileCoAuthLib64.dll OR *\\AppData\\Local\\Microsoft\\OneDrive\\*\\FileSyncShell64.dll OR *\\AppData\\Local\\Microsoft\\TeamsMeetingAddin\\*\\Microsoft.Teams.AddinLoader.dll))))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/a0ff33d8-79e4-4cef-b4f3-9dc4133ccd12 <<EOF
{
  "metadata": {
    "title": "Windows Registry Persistence COM Search Order Hijacking",
    "description": "Detects potential COM object hijacking leveraging the COM Search Order",
    "tags": [
      "attack.persistence",
      "attack.t1038"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND (winlog.event_id:\"13\" AND winlog.event_data.TargetObject.keyword:HKU\\\\*_Classes\\\\CLSID\\\\*\\\\InProcServer32\\\\\\(Default\\)) AND (NOT (winlog.event_data.Details.keyword:(%%systemroot%%\\\\system32\\\\* OR %%systemroot%%\\\\SysWow64\\\\* OR *\\\\AppData\\\\Local\\\\Microsoft\\\\OneDrive\\\\*\\\\FileCoAuthLib64.dll OR *\\\\AppData\\\\Local\\\\Microsoft\\\\OneDrive\\\\*\\\\FileSyncShell64.dll OR *\\\\AppData\\\\Local\\\\Microsoft\\\\TeamsMeetingAddin\\\\*\\\\Microsoft.Teams.AddinLoader.dll))))"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND (winlog.event_id:\"13\" AND winlog.event_data.TargetObject.keyword:HKU\\\\*_Classes\\\\CLSID\\\\*\\\\InProcServer32\\\\\\(Default\\)) AND (NOT (winlog.event_data.Details.keyword:(%%systemroot%%\\\\system32\\\\* OR %%systemroot%%\\\\SysWow64\\\\* OR *\\\\AppData\\\\Local\\\\Microsoft\\\\OneDrive\\\\*\\\\FileCoAuthLib64.dll OR *\\\\AppData\\\\Local\\\\Microsoft\\\\OneDrive\\\\*\\\\FileSyncShell64.dll OR *\\\\AppData\\\\Local\\\\Microsoft\\\\TeamsMeetingAddin\\\\*\\\\Microsoft.Teams.AddinLoader.dll))))",
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
        "subject": "Sigma Rule 'Windows Registry Persistence COM Search Order Hijacking'",
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
((EventID:"13" AND TargetObject.keyword:HKU\\*_Classes\\CLSID\\*\\InProcServer32\\\(Default\)) AND (NOT (Details.keyword:(%%systemroot%%\\system32\\* %%systemroot%%\\SysWow64\\* *\\AppData\\Local\\Microsoft\\OneDrive\\*\\FileCoAuthLib64.dll *\\AppData\\Local\\Microsoft\\OneDrive\\*\\FileSyncShell64.dll *\\AppData\\Local\\Microsoft\\TeamsMeetingAddin\\*\\Microsoft.Teams.AddinLoader.dll))))
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode="13" TargetObject="HKU\\*_Classes\\CLSID\\*\\InProcServer32\\(Default)") NOT ((Details="%%systemroot%%\\system32\\*" OR Details="%%systemroot%%\\SysWow64\\*" OR Details="*\\AppData\\Local\\Microsoft\\OneDrive\\*\\FileCoAuthLib64.dll" OR Details="*\\AppData\\Local\\Microsoft\\OneDrive\\*\\FileSyncShell64.dll" OR Details="*\\AppData\\Local\\Microsoft\\TeamsMeetingAddin\\*\\Microsoft.Teams.AddinLoader.dll")))
```


### logpoint
    
```
((event_id="13" TargetObject="HKU\\*_Classes\\CLSID\\*\\InProcServer32\\(Default)")  -(Details IN ["%%systemroot%%\\system32\\*", "%%systemroot%%\\SysWow64\\*", "*\\AppData\\Local\\Microsoft\\OneDrive\\*\\FileCoAuthLib64.dll", "*\\AppData\\Local\\Microsoft\\OneDrive\\*\\FileSyncShell64.dll", "*\\AppData\\Local\\Microsoft\\TeamsMeetingAddin\\*\\Microsoft.Teams.AddinLoader.dll"]))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*13)(?=.*HKU\\.*_Classes\CLSID\\.*\InProcServer32\\(Default\))))(?=.*(?!.*(?:.*(?=.*(?:.*%%systemroot%%\system32\\.*|.*%%systemroot%%\SysWow64\\.*|.*.*\AppData\Local\Microsoft\OneDrive\\.*\FileCoAuthLib64\.dll|.*.*\AppData\Local\Microsoft\OneDrive\\.*\FileSyncShell64\.dll|.*.*\AppData\Local\Microsoft\TeamsMeetingAddin\\.*\Microsoft\.Teams\.AddinLoader\.dll))))))'
```



