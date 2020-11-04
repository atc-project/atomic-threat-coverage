| Title                    | New DLL Added to AppCertDlls Registry Key       |
|:-------------------------|:------------------|
| **Description**          | Dynamic-link libraries (DLLs) that are specified in the AppCertDLLs value in the Registry key can be abused to obtain persistence and privilege escalation by causing a malicious DLL to be loaded and run in the context of separate processes on the computer. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1182: AppCert DLLs](https://attack.mitre.org/techniques/T1182)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0016_12_windows_sysmon_RegistryEvent](../Data_Needed/DN_0016_12_windows_sysmon_RegistryEvent.md)</li><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li><li>[DN_0018_14_windows_sysmon_RegistryEvent](../Data_Needed/DN_0018_14_windows_sysmon_RegistryEvent.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Unkown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[http://www.hexacorn.com/blog/2013/01/19/beyond-good-ol-run-key-part-3/](http://www.hexacorn.com/blog/2013/01/19/beyond-good-ol-run-key-part-3/)</li><li>[https://eqllib.readthedocs.io/en/latest/analytics/14f90406-10a0-4d36-a672-31cabe149f2f.html](https://eqllib.readthedocs.io/en/latest/analytics/14f90406-10a0-4d36-a672-31cabe149f2f.html)</li></ul>  |
| **Author**               | Ilyas Ochkov, oscd.community |


## Detection Rules

### Sigma rule

```
title: New DLL Added to AppCertDlls Registry Key
id: 6aa1d992-5925-4e9f-a49b-845e51d1de01
status: experimental
description: Dynamic-link libraries (DLLs) that are specified in the AppCertDLLs value in the Registry key can be abused to obtain persistence and privilege escalation
    by causing a malicious DLL to be loaded and run in the context of separate processes on the computer.
references:
    - http://www.hexacorn.com/blog/2013/01/19/beyond-good-ol-run-key-part-3/
    - https://eqllib.readthedocs.io/en/latest/analytics/14f90406-10a0-4d36-a672-31cabe149f2f.html
tags:
    - attack.persistence
    - attack.t1182
author: Ilyas Ochkov, oscd.community
date: 2019/10/25
modified: 2019/11/13
logsource:
    product: windows
    service: sysmon
detection:
    selection:
      - EventID: 
            - 12  # key create
            - 13  # value set
        # Sysmon gives us HKLM\SYSTEM\CurrentControlSet\.. if ControlSetXX is the selected one
        TargetObject: 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls'
      - EventID: 14  # key rename
        NewName: 'HKLM\SYSTEM\CurentControlSet\Control\Session Manager\AppCertDlls'
    condition: selection
fields:
    - EventID
    - Image
    - TargetObject
    - NewName
falsepositives:
    - Unkown
level: medium

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(((($_.ID -eq "12" -or $_.ID -eq "13") -and $_.message -match "TargetObject.*HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls") -or ($_.ID -eq "14" -and $_.message -match "NewName.*HKLM\\SYSTEM\\CurentControlSet\\Control\\Session Manager\\AppCertDlls"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND ((winlog.event_id:("12" OR "13") AND winlog.event_data.TargetObject:"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session\ Manager\\AppCertDlls") OR (winlog.event_id:"14" AND NewName:"HKLM\\SYSTEM\\CurentControlSet\\Control\\Session\ Manager\\AppCertDlls")))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/6aa1d992-5925-4e9f-a49b-845e51d1de01 <<EOF
{
  "metadata": {
    "title": "New DLL Added to AppCertDlls Registry Key",
    "description": "Dynamic-link libraries (DLLs) that are specified in the AppCertDLLs value in the Registry key can be abused to obtain persistence and privilege escalation by causing a malicious DLL to be loaded and run in the context of separate processes on the computer.",
    "tags": [
      "attack.persistence",
      "attack.t1182"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND ((winlog.event_id:(\"12\" OR \"13\") AND winlog.event_data.TargetObject:\"HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\Session\\ Manager\\\\AppCertDlls\") OR (winlog.event_id:\"14\" AND NewName:\"HKLM\\\\SYSTEM\\\\CurentControlSet\\\\Control\\\\Session\\ Manager\\\\AppCertDlls\")))"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND ((winlog.event_id:(\"12\" OR \"13\") AND winlog.event_data.TargetObject:\"HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\Session\\ Manager\\\\AppCertDlls\") OR (winlog.event_id:\"14\" AND NewName:\"HKLM\\\\SYSTEM\\\\CurentControlSet\\\\Control\\\\Session\\ Manager\\\\AppCertDlls\")))",
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
        "subject": "Sigma Rule 'New DLL Added to AppCertDlls Registry Key'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\n     EventID = {{_source.EventID}}\n       Image = {{_source.Image}}\nTargetObject = {{_source.TargetObject}}\n     NewName = {{_source.NewName}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
((EventID:("12" "13") AND TargetObject:"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls") OR (EventID:"14" AND NewName:"HKLM\\SYSTEM\\CurentControlSet\\Control\\Session Manager\\AppCertDlls"))
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" (((EventCode="12" OR EventCode="13") TargetObject="HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls") OR (EventCode="14" NewName="HKLM\\SYSTEM\\CurentControlSet\\Control\\Session Manager\\AppCertDlls"))) | table EventCode,Image,TargetObject,NewName
```


### logpoint
    
```
((event_id IN ["12", "13"] TargetObject="HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls") OR (event_id="14" NewName="HKLM\\SYSTEM\\CurentControlSet\\Control\\Session Manager\\AppCertDlls"))
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*(?=.*(?:.*12|.*13))(?=.*HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls))|.*(?:.*(?=.*14)(?=.*HKLM\SYSTEM\CurentControlSet\Control\Session Manager\AppCertDlls))))'
```



