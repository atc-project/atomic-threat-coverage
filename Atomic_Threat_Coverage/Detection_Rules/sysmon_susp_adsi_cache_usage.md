| Title                    | Suspicious ADSI-Cache Usage By Unknown Tool       |
|:-------------------------|:------------------|
| **Description**          | detects the usage of ADSI (LDAP) operations by tools. This may also detect tools like LDAPFragger. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1041: Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0015_11_windows_sysmon_FileCreate](../Data_Needed/DN_0015_11_windows_sysmon_FileCreate.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Other legimate tools, which do ADSI (LDAP) operations, e.g. any remoting activity by MMC, Powershell, Windows etc.</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://medium.com/@ivecodoe/detecting-ldapfragger-a-newly-released-cobalt-strike-beacon-using-ldap-for-c2-communication-c274a7f00961](https://medium.com/@ivecodoe/detecting-ldapfragger-a-newly-released-cobalt-strike-beacon-using-ldap-for-c2-communication-c274a7f00961)</li><li>[https://blog.fox-it.com/2020/03/19/ldapfragger-command-and-control-over-ldap-attributes/](https://blog.fox-it.com/2020/03/19/ldapfragger-command-and-control-over-ldap-attributes/)</li><li>[https://github.com/fox-it/LDAPFragger](https://github.com/fox-it/LDAPFragger)</li></ul>  |
| **Author**               | xknow @xknow_infosec |


## Detection Rules

### Sigma rule

```
title: Suspicious ADSI-Cache Usage By Unknown Tool
id: 75bf09fa-1dd7-4d18-9af9-dd9e492562eb
description: detects the usage of ADSI (LDAP) operations by tools. This may also detect tools like LDAPFragger.
status: experimental
date: 2019/03/24
author: xknow @xknow_infosec
references:
    - https://medium.com/@ivecodoe/detecting-ldapfragger-a-newly-released-cobalt-strike-beacon-using-ldap-for-c2-communication-c274a7f00961
    - https://blog.fox-it.com/2020/03/19/ldapfragger-command-and-control-over-ldap-attributes/
    - https://github.com/fox-it/LDAPFragger
tags:
    - attack.t1041
    - attack.persistence
logsource:
    product: windows
    service: sysmon
detection:
    selection_1:
        EventID: 11
        TargetFilename: '*\Local\Microsoft\Windows\SchCache\*.sch'
    selection_2:
        Image|contains:
            - 'C:\windows\system32\svchost.exe'
            - 'C:\windows\system32\dllhost.exe'
            - 'C:\windows\system32\mmc.exe'
            - 'C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe'
    condition: selection_1 and not selection_2
falsepositives:
    - Other legimate tools, which do ADSI (LDAP) operations, e.g. any remoting activity by MMC, Powershell, Windows etc.
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "11" -and $_.message -match "TargetFilename.*.*\\Local\\Microsoft\\Windows\\SchCache\\.*.sch") -and  -not (($_.message -match "Image.*.*C:\\windows\\system32\\svchost.exe.*" -or $_.message -match "Image.*.*C:\\windows\\system32\\dllhost.exe.*" -or $_.message -match "Image.*.*C:\\windows\\system32\\mmc.exe.*" -or $_.message -match "Image.*.*C:\\windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND (winlog.event_id:"11" AND winlog.event_data.TargetFilename.keyword:*\\Local\\Microsoft\\Windows\\SchCache\*.sch) AND (NOT (winlog.event_data.Image.keyword:(*C\:\\windows\\system32\\svchost.exe* OR *C\:\\windows\\system32\\dllhost.exe* OR *C\:\\windows\\system32\\mmc.exe* OR *C\:\\windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe*))))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/75bf09fa-1dd7-4d18-9af9-dd9e492562eb <<EOF
{
  "metadata": {
    "title": "Suspicious ADSI-Cache Usage By Unknown Tool",
    "description": "detects the usage of ADSI (LDAP) operations by tools. This may also detect tools like LDAPFragger.",
    "tags": [
      "attack.t1041",
      "attack.persistence"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND (winlog.event_id:\"11\" AND winlog.event_data.TargetFilename.keyword:*\\\\Local\\\\Microsoft\\\\Windows\\\\SchCache\\*.sch) AND (NOT (winlog.event_data.Image.keyword:(*C\\:\\\\windows\\\\system32\\\\svchost.exe* OR *C\\:\\\\windows\\\\system32\\\\dllhost.exe* OR *C\\:\\\\windows\\\\system32\\\\mmc.exe* OR *C\\:\\\\windows\\\\system32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe*))))"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND (winlog.event_id:\"11\" AND winlog.event_data.TargetFilename.keyword:*\\\\Local\\\\Microsoft\\\\Windows\\\\SchCache\\*.sch) AND (NOT (winlog.event_data.Image.keyword:(*C\\:\\\\windows\\\\system32\\\\svchost.exe* OR *C\\:\\\\windows\\\\system32\\\\dllhost.exe* OR *C\\:\\\\windows\\\\system32\\\\mmc.exe* OR *C\\:\\\\windows\\\\system32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe*))))",
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
        "subject": "Sigma Rule 'Suspicious ADSI-Cache Usage By Unknown Tool'",
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
((EventID:"11" AND TargetFilename.keyword:*\\Local\\Microsoft\\Windows\\SchCache\*.sch) AND (NOT (Image.keyword:(*C\:\\windows\\system32\\svchost.exe* *C\:\\windows\\system32\\dllhost.exe* *C\:\\windows\\system32\\mmc.exe* *C\:\\windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe*))))
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode="11" TargetFilename="*\\Local\\Microsoft\\Windows\\SchCache\*.sch") NOT ((Image="*C:\\windows\\system32\\svchost.exe*" OR Image="*C:\\windows\\system32\\dllhost.exe*" OR Image="*C:\\windows\\system32\\mmc.exe*" OR Image="*C:\\windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe*")))
```


### logpoint
    
```
((event_id="11" TargetFilename="*\\Local\\Microsoft\\Windows\\SchCache\*.sch")  -(Image IN ["*C:\\windows\\system32\\svchost.exe*", "*C:\\windows\\system32\\dllhost.exe*", "*C:\\windows\\system32\\mmc.exe*", "*C:\\windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe*"]))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*11)(?=.*.*\Local\Microsoft\Windows\SchCache\.*\.sch)))(?=.*(?!.*(?:.*(?=.*(?:.*.*C:\windows\system32\svchost\.exe.*|.*.*C:\windows\system32\dllhost\.exe.*|.*.*C:\windows\system32\mmc\.exe.*|.*.*C:\windows\system32\WindowsPowerShell\v1\.0\powershell\.exe.*))))))'
```



