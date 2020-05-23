| Title                    | Winnti Malware HK University Campaign       |
|:-------------------------|:------------------|
| **Description**          | Detects specific process characteristics of Winnti malware noticed in Dec/Jan 2020 in a campaign against Honk Kong universities |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1073: DLL Side-Loading](https://attack.mitre.org/techniques/T1073)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1073: DLL Side-Loading](../Triggers/T1073.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Unlikely</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.welivesecurity.com/2020/01/31/winnti-group-targeting-universities-hong-kong/](https://www.welivesecurity.com/2020/01/31/winnti-group-targeting-universities-hong-kong/)</li></ul>  |
| **Author**               | Florian Roth, Markus Neis |
| Other Tags           | <ul><li>attack.g0044</li></ul> | 

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
Get-WinEvent | where {((($_.message -match "ParentImage.*.*C:\\\\Windows\\\\Temp.*" -or $_.message -match "ParentImage.*.*\\\\hpqhvind.exe.*") -and $_.message -match "Image.*C:\\\\ProgramData\\\\DRM.*") -or ($_.message -match "ParentImage.*C:\\\\ProgramData\\\\DRM.*" -and $_.message -match "Image.*.*\\\\wmplayer.exe") -or ($_.message -match "ParentImage.*.*\\\\Test.exe" -and $_.message -match "Image.*.*\\\\wmplayer.exe") -or $_.message -match "Image.*C:\\\\ProgramData\\\\DRM\\\\CLR\\\\CLR.exe" -or ($_.message -match "ParentImage.*C:\\\\ProgramData\\\\DRM\\\\Windows.*" -and $_.message -match "Image.*.*\\\\SearchFilterHost.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
((winlog.event_data.ParentImage.keyword:(*C\\:\\\\Windows\\\\Temp* OR *\\\\hpqhvind.exe*) AND winlog.event_data.Image.keyword:C\\:\\\\ProgramData\\\\DRM*) OR (winlog.event_data.ParentImage.keyword:C\\:\\\\ProgramData\\\\DRM* AND winlog.event_data.Image.keyword:*\\\\wmplayer.exe) OR (winlog.event_data.ParentImage.keyword:*\\\\Test.exe AND winlog.event_data.Image.keyword:*\\\\wmplayer.exe) OR winlog.event_data.Image:"C\\:\\\\ProgramData\\\\DRM\\\\CLR\\\\CLR.exe" OR (winlog.event_data.ParentImage.keyword:C\\:\\\\ProgramData\\\\DRM\\\\Windows* AND winlog.event_data.Image.keyword:*\\\\SearchFilterHost.exe))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/3121461b-5aa0-4a41-b910-66d25524edbb <<EOF\n{\n  "metadata": {\n    "title": "Winnti Malware HK University Campaign",\n    "description": "Detects specific process characteristics of Winnti malware noticed in Dec/Jan 2020 in a campaign against Honk Kong universities",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1073",\n      "attack.g0044"\n    ],\n    "query": "((winlog.event_data.ParentImage.keyword:(*C\\\\:\\\\\\\\Windows\\\\\\\\Temp* OR *\\\\\\\\hpqhvind.exe*) AND winlog.event_data.Image.keyword:C\\\\:\\\\\\\\ProgramData\\\\\\\\DRM*) OR (winlog.event_data.ParentImage.keyword:C\\\\:\\\\\\\\ProgramData\\\\\\\\DRM* AND winlog.event_data.Image.keyword:*\\\\\\\\wmplayer.exe) OR (winlog.event_data.ParentImage.keyword:*\\\\\\\\Test.exe AND winlog.event_data.Image.keyword:*\\\\\\\\wmplayer.exe) OR winlog.event_data.Image:\\"C\\\\:\\\\\\\\ProgramData\\\\\\\\DRM\\\\\\\\CLR\\\\\\\\CLR.exe\\" OR (winlog.event_data.ParentImage.keyword:C\\\\:\\\\\\\\ProgramData\\\\\\\\DRM\\\\\\\\Windows* AND winlog.event_data.Image.keyword:*\\\\\\\\SearchFilterHost.exe))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((winlog.event_data.ParentImage.keyword:(*C\\\\:\\\\\\\\Windows\\\\\\\\Temp* OR *\\\\\\\\hpqhvind.exe*) AND winlog.event_data.Image.keyword:C\\\\:\\\\\\\\ProgramData\\\\\\\\DRM*) OR (winlog.event_data.ParentImage.keyword:C\\\\:\\\\\\\\ProgramData\\\\\\\\DRM* AND winlog.event_data.Image.keyword:*\\\\\\\\wmplayer.exe) OR (winlog.event_data.ParentImage.keyword:*\\\\\\\\Test.exe AND winlog.event_data.Image.keyword:*\\\\\\\\wmplayer.exe) OR winlog.event_data.Image:\\"C\\\\:\\\\\\\\ProgramData\\\\\\\\DRM\\\\\\\\CLR\\\\\\\\CLR.exe\\" OR (winlog.event_data.ParentImage.keyword:C\\\\:\\\\\\\\ProgramData\\\\\\\\DRM\\\\\\\\Windows* AND winlog.event_data.Image.keyword:*\\\\\\\\SearchFilterHost.exe))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Winnti Malware HK University Campaign\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((ParentImage.keyword:(*C\\:\\\\Windows\\\\Temp* *\\\\hpqhvind.exe*) AND Image.keyword:C\\:\\\\ProgramData\\\\DRM*) OR (ParentImage.keyword:C\\:\\\\ProgramData\\\\DRM* AND Image.keyword:*\\\\wmplayer.exe) OR (ParentImage.keyword:*\\\\Test.exe AND Image.keyword:*\\\\wmplayer.exe) OR Image:"C\\:\\\\ProgramData\\\\DRM\\\\CLR\\\\CLR.exe" OR (ParentImage.keyword:C\\:\\\\ProgramData\\\\DRM\\\\Windows* AND Image.keyword:*\\\\SearchFilterHost.exe))
```


### splunk
    
```
(((ParentImage="*C:\\\\Windows\\\\Temp*" OR ParentImage="*\\\\hpqhvind.exe*") Image="C:\\\\ProgramData\\\\DRM*") OR (ParentImage="C:\\\\ProgramData\\\\DRM*" Image="*\\\\wmplayer.exe") OR (ParentImage="*\\\\Test.exe" Image="*\\\\wmplayer.exe") OR Image="C:\\\\ProgramData\\\\DRM\\\\CLR\\\\CLR.exe" OR (ParentImage="C:\\\\ProgramData\\\\DRM\\\\Windows*" Image="*\\\\SearchFilterHost.exe"))
```


### logpoint
    
```
((ParentImage IN ["*C:\\\\Windows\\\\Temp*", "*\\\\hpqhvind.exe*"] Image="C:\\\\ProgramData\\\\DRM*") OR (ParentImage="C:\\\\ProgramData\\\\DRM*" Image="*\\\\wmplayer.exe") OR (ParentImage="*\\\\Test.exe" Image="*\\\\wmplayer.exe") OR Image="C:\\\\ProgramData\\\\DRM\\\\CLR\\\\CLR.exe" OR (ParentImage="C:\\\\ProgramData\\\\DRM\\\\Windows*" Image="*\\\\SearchFilterHost.exe"))
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*(?=.*(?:.*.*C:\\Windows\\Temp.*|.*.*\\hpqhvind\\.exe.*))(?=.*C:\\ProgramData\\DRM.*))|.*(?:.*(?=.*C:\\ProgramData\\DRM.*)(?=.*.*\\wmplayer\\.exe))|.*(?:.*(?=.*.*\\Test\\.exe)(?=.*.*\\wmplayer\\.exe))|.*C:\\ProgramData\\DRM\\CLR\\CLR\\.exe|.*(?:.*(?=.*C:\\ProgramData\\DRM\\Windows.*)(?=.*.*\\SearchFilterHost\\.exe))))'
```



