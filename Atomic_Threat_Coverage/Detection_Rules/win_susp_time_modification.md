| Title                    | Unauthorized System Time Modification       |
|:-------------------------|:------------------|
| **Description**          | Detect scenarios where a potentially unauthorized application or user is modifying the system time. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1099: Timestomp](https://attack.mitre.org/techniques/T1099)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>HyperV or other virtualization technologies with binary not listed in filter portion of detection</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[Private Cuckoo Sandbox (from many years ago, no longer have hash, NDA as well)](Private Cuckoo Sandbox (from many years ago, no longer have hash, NDA as well))</li><li>[Live environment caused by malware](Live environment caused by malware)</li></ul>  |
| **Author**               | @neu5ron |
| Other Tags           | <ul><li>attack.t1551.006</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Unauthorized System Time Modification
id: faa031b5-21ed-4e02-8881-2591f98d82ed
status: experimental
description: Detect scenarios where a potentially unauthorized application or user is modifying the system time.
author: '@neu5ron'
references:
    - Private Cuckoo Sandbox (from many years ago, no longer have hash, NDA as well)
    - Live environment caused by malware
date: 2019/02/05
midified: 2020/01/27
tags:
    - attack.defense_evasion
    - attack.t1099
    - attack.t1551.006
logsource:
    product: windows
    service: security
    definition: 'Requirements: Audit Policy : System > Audit Security State Change, Group Policy : Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\System\Audit Security State Change'
detection:
    selection:
        EventID: 4616
    filter1:
        ProcessName: 'C:\Program Files\VMware\VMware Tools\vmtoolsd.exe'
    filter2:
        ProcessName: 'C:\Windows\System32\VBoxService.exe'
    filter3:
        ProcessName: 'C:\Windows\System32\svchost.exe'
        SubjectUserSid: 'S-1-5-19'
    condition: selection and not ( filter1 or filter2 or filter3 )
falsepositives:
    - HyperV or other virtualization technologies with binary not listed in filter portion of detection
level: medium

```





### powershell
    
```
Get-WinEvent -LogName Security | where {($_.ID -eq "4616" -and  -not (((($_.message -match "ProcessName.*C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe" -or $_.message -match "ProcessName.*C:\\Windows\\System32\\VBoxService.exe") -or ($_.message -match "ProcessName.*C:\\Windows\\System32\\svchost.exe" -and $_.message -match "SubjectUserSid.*S-1-5-19"))))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND winlog.event_id:"4616" AND (NOT ((winlog.channel:"Security" AND ((winlog.event_data.ProcessName:"C\:\\Program\ Files\\VMware\\VMware\ Tools\\vmtoolsd.exe" OR winlog.event_data.ProcessName:"C\:\\Windows\\System32\\VBoxService.exe") OR (winlog.event_data.ProcessName:"C\:\\Windows\\System32\\svchost.exe" AND winlog.event_data.SubjectUserSid:"S\-1\-5\-19"))))))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/faa031b5-21ed-4e02-8881-2591f98d82ed <<EOF
{
  "metadata": {
    "title": "Unauthorized System Time Modification",
    "description": "Detect scenarios where a potentially unauthorized application or user is modifying the system time.",
    "tags": [
      "attack.defense_evasion",
      "attack.t1099",
      "attack.t1551.006"
    ],
    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"4616\" AND (NOT ((winlog.channel:\"Security\" AND ((winlog.event_data.ProcessName:\"C\\:\\\\Program\\ Files\\\\VMware\\\\VMware\\ Tools\\\\vmtoolsd.exe\" OR winlog.event_data.ProcessName:\"C\\:\\\\Windows\\\\System32\\\\VBoxService.exe\") OR (winlog.event_data.ProcessName:\"C\\:\\\\Windows\\\\System32\\\\svchost.exe\" AND winlog.event_data.SubjectUserSid:\"S\\-1\\-5\\-19\"))))))"
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
                    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"4616\" AND (NOT ((winlog.channel:\"Security\" AND ((winlog.event_data.ProcessName:\"C\\:\\\\Program\\ Files\\\\VMware\\\\VMware\\ Tools\\\\vmtoolsd.exe\" OR winlog.event_data.ProcessName:\"C\\:\\\\Windows\\\\System32\\\\VBoxService.exe\") OR (winlog.event_data.ProcessName:\"C\\:\\\\Windows\\\\System32\\\\svchost.exe\" AND winlog.event_data.SubjectUserSid:\"S\\-1\\-5\\-19\"))))))",
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
      "throttle_period": "15m",
      "email": {
        "profile": "standard",
        "from": "root@localhost",
        "to": "root@localhost",
        "subject": "Sigma Rule 'Unauthorized System Time Modification'",
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
(EventID:"4616" AND (NOT (((ProcessName:"C\:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe" OR ProcessName:"C\:\\Windows\\System32\\VBoxService.exe") OR (ProcessName:"C\:\\Windows\\System32\\svchost.exe" AND SubjectUserSid:"S\-1\-5\-19")))))
```


### splunk
    
```
(source="WinEventLog:Security" EventCode="4616" NOT ((source="WinEventLog:Security" ((ProcessName="C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe" OR ProcessName="C:\\Windows\\System32\\VBoxService.exe") OR (ProcessName="C:\\Windows\\System32\\svchost.exe" SubjectUserSid="S-1-5-19")))))
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="4616"  -((event_source="Microsoft-Windows-Security-Auditing" ((ProcessName="C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe" OR ProcessName="C:\\Windows\\System32\\VBoxService.exe") OR (ProcessName="C:\\Windows\\System32\\svchost.exe" SubjectUserSid="S-1-5-19")))))
```


### grep
    
```
grep -P '^(?:.*(?=.*4616)(?=.*(?!.*(?:.*(?:.*(?:.*(?:.*(?:.*C:\Program Files\VMware\VMware Tools\vmtoolsd\.exe|.*C:\Windows\System32\VBoxService\.exe))|.*(?:.*(?=.*C:\Windows\System32\svchost\.exe)(?=.*S-1-5-19))))))))'
```



