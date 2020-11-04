| Title                    | Winlogon Helper DLL       |
|:-------------------------|:------------------|
| **Description**          | Winlogon.exe is a Windows component responsible for actions at logon/logoff as well as the secure attention sequence (SAS) triggered by Ctrl-Alt-Delete. Registry entries in HKLM\Software[Wow6432Node]Microsoft\Windows NT\CurrentVersion\Winlogon\ and HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ are used to manage additional helper programs and functionalities that support Winlogon. Malicious modifications to these Registry keys may cause Winlogon to load and execute malicious DLLs and/or executables. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1004: Winlogon Helper DLL](https://attack.mitre.org/techniques/T1004)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0036_4104_windows_powershell_script_block](../Data_Needed/DN_0036_4104_windows_powershell_script_block.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1004: Winlogon Helper DLL](../Triggers/T1004.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1004/T1004.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1004/T1004.yaml)</li></ul>  |
| **Author**               | Timur Zinniatullin, oscd.community |


## Detection Rules

### Sigma rule

```
title: Winlogon Helper DLL
id: 851c506b-6b7c-4ce2-8802-c703009d03c0
status: experimental
description: Winlogon.exe is a Windows component responsible for actions at logon/logoff as well as the secure attention sequence (SAS) triggered by Ctrl-Alt-Delete.
    Registry entries in HKLM\Software[Wow6432Node]Microsoft\Windows NT\CurrentVersion\Winlogon\ and HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ are
    used to manage additional helper programs and functionalities that support Winlogon. Malicious modifications to these Registry keys may cause Winlogon to load
    and execute malicious DLLs and/or executables.
author: Timur Zinniatullin, oscd.community
date: 2019/10/21
modified: 2019/11/04
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1004/T1004.yaml
logsource:
    product: windows
    service: powershell
    description: 'Script block logging must be enabled'
detection:
    selection:
        EventID: 4104
    keyword1: 
        - '*Set-ItemProperty*'
        - '*New-Item*'
    keyword2: 
        - '*CurrentVersion\Winlogon*'
    condition: selection and ( keyword1 and keyword2 )
falsepositives:
    - Unknown
level: medium
tags:
    - attack.persistence
    - attack.t1004

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {($_.ID -eq "4104" -and ($_.message -match "*Set-ItemProperty*" -or $_.message -match "*New-Item*") -and $_.message -match "*CurrentVersion\Winlogon*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_id:"4104" AND \*.keyword:(*Set\-ItemProperty* OR *New\-Item*) AND "*CurrentVersion\\Winlogon*")
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/851c506b-6b7c-4ce2-8802-c703009d03c0 <<EOF
{
  "metadata": {
    "title": "Winlogon Helper DLL",
    "description": "Winlogon.exe is a Windows component responsible for actions at logon/logoff as well as the secure attention sequence (SAS) triggered by Ctrl-Alt-Delete. Registry entries in HKLM\\Software[Wow6432Node]Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\ and HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\ are used to manage additional helper programs and functionalities that support Winlogon. Malicious modifications to these Registry keys may cause Winlogon to load and execute malicious DLLs and/or executables.",
    "tags": [
      "attack.persistence",
      "attack.t1004"
    ],
    "query": "(winlog.event_id:\"4104\" AND \\*.keyword:(*Set\\-ItemProperty* OR *New\\-Item*) AND \"*CurrentVersion\\\\Winlogon*\")"
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
                    "query": "(winlog.event_id:\"4104\" AND \\*.keyword:(*Set\\-ItemProperty* OR *New\\-Item*) AND \"*CurrentVersion\\\\Winlogon*\")",
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
        "subject": "Sigma Rule 'Winlogon Helper DLL'",
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
(EventID:"4104" AND \*.keyword:(*Set\-ItemProperty* OR *New\-Item*) AND "*CurrentVersion\\Winlogon*")
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="4104" ("*Set-ItemProperty*" OR "*New-Item*") "*CurrentVersion\\Winlogon*")
```


### logpoint
    
```
(event_id="4104" ("*Set-ItemProperty*" OR "*New-Item*") "*CurrentVersion\\Winlogon*")
```


### grep
    
```
grep -P '^(?:.*(?=.*4104)(?=.*(?:.*(?:.*.*Set-ItemProperty.*|.*.*New-Item.*)))(?=.*.*CurrentVersion\Winlogon.*))'
```



