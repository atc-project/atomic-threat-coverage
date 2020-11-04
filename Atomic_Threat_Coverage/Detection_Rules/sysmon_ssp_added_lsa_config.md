| Title                    | Security Support Provider (SSP) Added to LSA Configuration       |
|:-------------------------|:------------------|
| **Description**          | Detects the addition of a SSP to the registry. Upon a reboot or API call, SSP DLLs gain access to encrypted and plaintext passwords stored in Windows. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1011: Exfiltration Over Other Network Medium](https://attack.mitre.org/techniques/T1011)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Unlikely</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://attack.mitre.org/techniques/T1101/](https://attack.mitre.org/techniques/T1101/)</li><li>[https://powersploit.readthedocs.io/en/latest/Persistence/Install-SSP/](https://powersploit.readthedocs.io/en/latest/Persistence/Install-SSP/)</li></ul>  |
| **Author**               | iwillkeepwatch |


## Detection Rules

### Sigma rule

```
title: Security Support Provider (SSP) Added to LSA Configuration
id: eeb30123-9fbd-4ee8-aaa0-2e545bbed6dc
status: experimental
description: Detects the addition of a SSP to the registry. Upon a reboot or API call, SSP DLLs gain access to encrypted and plaintext passwords stored in Windows.
references:
    - https://attack.mitre.org/techniques/T1101/
    - https://powersploit.readthedocs.io/en/latest/Persistence/Install-SSP/
tags:
    - attack.persistence
    - attack.t1011
author: iwillkeepwatch
date: 2019/01/18
logsource:
    product: windows
    service: sysmon
detection:
    selection_registry:
        EventID: 13
        TargetObject:
            - 'HKLM\System\CurrentControlSet\Control\Lsa\Security Packages'
            - 'HKLM\System\CurrentControlSet\Control\Lsa\OSConfig\Security Packages'
    exclusion_images:
        - Image: C:\Windows\system32\msiexec.exe
        - Image: C:\Windows\syswow64\MsiExec.exe
    condition: selection_registry and not exclusion_images
falsepositives:
    - Unlikely
level: critical

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "13" -and ($_.message -match "HKLM\\System\\CurrentControlSet\\Control\\Lsa\\Security Packages" -or $_.message -match "HKLM\\System\\CurrentControlSet\\Control\\Lsa\\OSConfig\\Security Packages")) -and  -not ($_.message -match "Image.*C:\\Windows\\system32\\msiexec.exe" -or $_.message -match "Image.*C:\\Windows\\syswow64\\MsiExec.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND (winlog.event_id:"13" AND winlog.event_data.TargetObject:("HKLM\\System\\CurrentControlSet\\Control\\Lsa\\Security\ Packages" OR "HKLM\\System\\CurrentControlSet\\Control\\Lsa\\OSConfig\\Security\ Packages")) AND (NOT (winlog.event_data.Image:"C\:\\Windows\\system32\\msiexec.exe" OR winlog.event_data.Image:"C\:\\Windows\\syswow64\\MsiExec.exe")))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/eeb30123-9fbd-4ee8-aaa0-2e545bbed6dc <<EOF
{
  "metadata": {
    "title": "Security Support Provider (SSP) Added to LSA Configuration",
    "description": "Detects the addition of a SSP to the registry. Upon a reboot or API call, SSP DLLs gain access to encrypted and plaintext passwords stored in Windows.",
    "tags": [
      "attack.persistence",
      "attack.t1011"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND (winlog.event_id:\"13\" AND winlog.event_data.TargetObject:(\"HKLM\\\\System\\\\CurrentControlSet\\\\Control\\\\Lsa\\\\Security\\ Packages\" OR \"HKLM\\\\System\\\\CurrentControlSet\\\\Control\\\\Lsa\\\\OSConfig\\\\Security\\ Packages\")) AND (NOT (winlog.event_data.Image:\"C\\:\\\\Windows\\\\system32\\\\msiexec.exe\" OR winlog.event_data.Image:\"C\\:\\\\Windows\\\\syswow64\\\\MsiExec.exe\")))"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND (winlog.event_id:\"13\" AND winlog.event_data.TargetObject:(\"HKLM\\\\System\\\\CurrentControlSet\\\\Control\\\\Lsa\\\\Security\\ Packages\" OR \"HKLM\\\\System\\\\CurrentControlSet\\\\Control\\\\Lsa\\\\OSConfig\\\\Security\\ Packages\")) AND (NOT (winlog.event_data.Image:\"C\\:\\\\Windows\\\\system32\\\\msiexec.exe\" OR winlog.event_data.Image:\"C\\:\\\\Windows\\\\syswow64\\\\MsiExec.exe\")))",
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
        "subject": "Sigma Rule 'Security Support Provider (SSP) Added to LSA Configuration'",
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
((EventID:"13" AND TargetObject:("HKLM\\System\\CurrentControlSet\\Control\\Lsa\\Security Packages" "HKLM\\System\\CurrentControlSet\\Control\\Lsa\\OSConfig\\Security Packages")) AND (NOT (Image:"C\:\\Windows\\system32\\msiexec.exe" OR Image:"C\:\\Windows\\syswow64\\MsiExec.exe")))
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode="13" (TargetObject="HKLM\\System\\CurrentControlSet\\Control\\Lsa\\Security Packages" OR TargetObject="HKLM\\System\\CurrentControlSet\\Control\\Lsa\\OSConfig\\Security Packages")) NOT (Image="C:\\Windows\\system32\\msiexec.exe" OR Image="C:\\Windows\\syswow64\\MsiExec.exe"))
```


### logpoint
    
```
((event_id="13" TargetObject IN ["HKLM\\System\\CurrentControlSet\\Control\\Lsa\\Security Packages", "HKLM\\System\\CurrentControlSet\\Control\\Lsa\\OSConfig\\Security Packages"])  -(Image="C:\\Windows\\system32\\msiexec.exe" OR Image="C:\\Windows\\syswow64\\MsiExec.exe"))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*13)(?=.*(?:.*HKLM\System\CurrentControlSet\Control\Lsa\Security Packages|.*HKLM\System\CurrentControlSet\Control\Lsa\OSConfig\Security Packages))))(?=.*(?!.*(?:.*(?:.*(?=.*C:\Windows\system32\msiexec\.exe)|.*(?=.*C:\Windows\syswow64\MsiExec\.exe))))))'
```



