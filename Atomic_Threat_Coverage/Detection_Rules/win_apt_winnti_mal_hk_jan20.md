| Title                    | Winnti Malware HK University Campaign       |
|:-------------------------|:------------------|
| **Description**          | Detects specific process characteristics of Winnti malware noticed in Dec/Jan 2020 in a campaign against Honk Kong universities |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1073: DLL Side-Loading](https://attack.mitre.org/techniques/T1073)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Unlikely</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.welivesecurity.com/2020/01/31/winnti-group-targeting-universities-hong-kong/](https://www.welivesecurity.com/2020/01/31/winnti-group-targeting-universities-hong-kong/)</li></ul>  |
| **Author**               | Florian Roth, Markus Neis |
| Other Tags           | <ul><li>attack.g0044</li><li>attack.t1574.002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Winnti Malware HK University Campaign
id: 3121461b-5aa0-4a41-b910-66d25524edbb
status: experimental
description: Detects specific process characteristics of Winnti malware noticed in Dec/Jan 2020 in a campaign against Honk Kong universities
references:
    - https://www.welivesecurity.com/2020/01/31/winnti-group-targeting-universities-hong-kong/
tags:
    - attack.defense_evasion
    - attack.t1073
    - attack.g0044
    - attack.t1574.002
author: Florian Roth, Markus Neis
date: 2020/02/01
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        ParentImage|contains:
            - 'C:\Windows\Temp'
            - '\hpqhvind.exe'
        Image|startswith: 'C:\ProgramData\DRM'
    selection2:
        ParentImage|startswith: 'C:\ProgramData\DRM'
        Image|endswith: '\wmplayer.exe'
    selection3:
        ParentImage|endswith: '\Test.exe'
        Image|endswith: '\wmplayer.exe'
    selection4:
        Image: 'C:\ProgramData\DRM\CLR\CLR.exe'
    selection5:
        ParentImage|startswith: 'C:\ProgramData\DRM\Windows'
        Image|endswith: '\SearchFilterHost.exe'
    condition: 1 of them
falsepositives:
    - Unlikely
level: critical

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ((($_.message -match "ParentImage.*.*C:\\Windows\\Temp.*" -or $_.message -match "ParentImage.*.*\\hpqhvind.exe.*") -and $_.message -match "Image.*C:\\ProgramData\\DRM.*") -or ($_.message -match "ParentImage.*C:\\ProgramData\\DRM.*" -and $_.message -match "Image.*.*\\wmplayer.exe") -or ($_.message -match "ParentImage.*.*\\Test.exe" -and $_.message -match "Image.*.*\\wmplayer.exe") -or $_.message -match "Image.*C:\\ProgramData\\DRM\\CLR\\CLR.exe" -or ($_.message -match "ParentImage.*C:\\ProgramData\\DRM\\Windows.*" -and $_.message -match "Image.*.*\\SearchFilterHost.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
((winlog.event_data.ParentImage.keyword:(*C\:\\Windows\\Temp* OR *\\hpqhvind.exe*) AND winlog.event_data.Image.keyword:C\:\\ProgramData\\DRM*) OR (winlog.event_data.ParentImage.keyword:C\:\\ProgramData\\DRM* AND winlog.event_data.Image.keyword:*\\wmplayer.exe) OR (winlog.event_data.ParentImage.keyword:*\\Test.exe AND winlog.event_data.Image.keyword:*\\wmplayer.exe) OR winlog.event_data.Image:"C\:\\ProgramData\\DRM\\CLR\\CLR.exe" OR (winlog.event_data.ParentImage.keyword:C\:\\ProgramData\\DRM\\Windows* AND winlog.event_data.Image.keyword:*\\SearchFilterHost.exe))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/3121461b-5aa0-4a41-b910-66d25524edbb <<EOF
{
  "metadata": {
    "title": "Winnti Malware HK University Campaign",
    "description": "Detects specific process characteristics of Winnti malware noticed in Dec/Jan 2020 in a campaign against Honk Kong universities",
    "tags": [
      "attack.defense_evasion",
      "attack.t1073",
      "attack.g0044",
      "attack.t1574.002"
    ],
    "query": "((winlog.event_data.ParentImage.keyword:(*C\\:\\\\Windows\\\\Temp* OR *\\\\hpqhvind.exe*) AND winlog.event_data.Image.keyword:C\\:\\\\ProgramData\\\\DRM*) OR (winlog.event_data.ParentImage.keyword:C\\:\\\\ProgramData\\\\DRM* AND winlog.event_data.Image.keyword:*\\\\wmplayer.exe) OR (winlog.event_data.ParentImage.keyword:*\\\\Test.exe AND winlog.event_data.Image.keyword:*\\\\wmplayer.exe) OR winlog.event_data.Image:\"C\\:\\\\ProgramData\\\\DRM\\\\CLR\\\\CLR.exe\" OR (winlog.event_data.ParentImage.keyword:C\\:\\\\ProgramData\\\\DRM\\\\Windows* AND winlog.event_data.Image.keyword:*\\\\SearchFilterHost.exe))"
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
                    "query": "((winlog.event_data.ParentImage.keyword:(*C\\:\\\\Windows\\\\Temp* OR *\\\\hpqhvind.exe*) AND winlog.event_data.Image.keyword:C\\:\\\\ProgramData\\\\DRM*) OR (winlog.event_data.ParentImage.keyword:C\\:\\\\ProgramData\\\\DRM* AND winlog.event_data.Image.keyword:*\\\\wmplayer.exe) OR (winlog.event_data.ParentImage.keyword:*\\\\Test.exe AND winlog.event_data.Image.keyword:*\\\\wmplayer.exe) OR winlog.event_data.Image:\"C\\:\\\\ProgramData\\\\DRM\\\\CLR\\\\CLR.exe\" OR (winlog.event_data.ParentImage.keyword:C\\:\\\\ProgramData\\\\DRM\\\\Windows* AND winlog.event_data.Image.keyword:*\\\\SearchFilterHost.exe))",
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
        "subject": "Sigma Rule 'Winnti Malware HK University Campaign'",
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
((ParentImage.keyword:(*C\:\\Windows\\Temp* *\\hpqhvind.exe*) AND Image.keyword:C\:\\ProgramData\\DRM*) OR (ParentImage.keyword:C\:\\ProgramData\\DRM* AND Image.keyword:*\\wmplayer.exe) OR (ParentImage.keyword:*\\Test.exe AND Image.keyword:*\\wmplayer.exe) OR Image:"C\:\\ProgramData\\DRM\\CLR\\CLR.exe" OR (ParentImage.keyword:C\:\\ProgramData\\DRM\\Windows* AND Image.keyword:*\\SearchFilterHost.exe))
```


### splunk
    
```
(((ParentImage="*C:\\Windows\\Temp*" OR ParentImage="*\\hpqhvind.exe*") Image="C:\\ProgramData\\DRM*") OR (ParentImage="C:\\ProgramData\\DRM*" Image="*\\wmplayer.exe") OR (ParentImage="*\\Test.exe" Image="*\\wmplayer.exe") OR Image="C:\\ProgramData\\DRM\\CLR\\CLR.exe" OR (ParentImage="C:\\ProgramData\\DRM\\Windows*" Image="*\\SearchFilterHost.exe"))
```


### logpoint
    
```
(event_id="1" ((ParentImage IN ["*C:\\Windows\\Temp*", "*\\hpqhvind.exe*"] Image="C:\\ProgramData\\DRM*") OR (ParentImage="C:\\ProgramData\\DRM*" Image="*\\wmplayer.exe") OR (ParentImage="*\\Test.exe" Image="*\\wmplayer.exe") OR Image="C:\\ProgramData\\DRM\\CLR\\CLR.exe" OR (ParentImage="C:\\ProgramData\\DRM\\Windows*" Image="*\\SearchFilterHost.exe")))
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*(?=.*(?:.*.*C:\Windows\Temp.*|.*.*\hpqhvind\.exe.*))(?=.*C:\ProgramData\DRM.*))|.*(?:.*(?=.*C:\ProgramData\DRM.*)(?=.*.*\wmplayer\.exe))|.*(?:.*(?=.*.*\Test\.exe)(?=.*.*\wmplayer\.exe))|.*C:\ProgramData\DRM\CLR\CLR\.exe|.*(?:.*(?=.*C:\ProgramData\DRM\Windows.*)(?=.*.*\SearchFilterHost\.exe))))'
```



