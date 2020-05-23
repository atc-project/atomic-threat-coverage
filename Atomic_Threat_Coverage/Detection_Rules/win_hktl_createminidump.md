| Title                    | CreateMiniDump Hacktool       |
|:-------------------------|:------------------|
| **Description**          | Detects the use of CreateMiniDump hack tool used to dump the LSASS process memory for credential extraction on the attacker's machine |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1003: Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0015_11_windows_sysmon_FileCreate](../Data_Needed/DN_0015_11_windows_sysmon_FileCreate.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1003: Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://ired.team/offensive-security/credential-access-and-credential-dumping/dumping-lsass-passwords-without-mimikatz-minidumpwritedump-av-signature-bypass](https://ired.team/offensive-security/credential-access-and-credential-dumping/dumping-lsass-passwords-without-mimikatz-minidumpwritedump-av-signature-bypass)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
action: global
title: CreateMiniDump Hacktool
id: 36d88494-1d43-4dc0-b3fa-35c8fea0ca9d
description: Detects the use of CreateMiniDump hack tool used to dump the LSASS process memory for credential extraction on the attacker's machine
author: Florian Roth
references:
    - https://ired.team/offensive-security/credential-access-and-credential-dumping/dumping-lsass-passwords-without-mimikatz-minidumpwritedump-av-signature-bypass
date: 2019/12/22
tags:
    - attack.credential_access
    - attack.t1003
falsepositives:
    - Unknown
level: high
---
logsource:
    category: process_creation
    product: windows
detection:
    selection1: 
        Image|contains: '\CreateMiniDump.exe'
    selection2:
        Imphash: '4a07f944a83e8a7c2525efa35dd30e2f'
    condition: 1 of them
---
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 11
        TargetFileName|contains: '*\lsass.dmp'
    condition: 1 of them

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "Image.*.*\\\\CreateMiniDump.exe.*" -or $_.message -match "Imphash.*4a07f944a83e8a7c2525efa35dd30e2f") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message\nGet-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "11" -and $_.message -match "TargetFileName.*.*\\\\lsass.dmp.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:*\\\\CreateMiniDump.exe* OR winlog.event_data.Imphash:"4a07f944a83e8a7c2525efa35dd30e2f")\n(winlog.channel:"Microsoft\\-Windows\\-Sysmon\\/Operational" AND winlog.event_id:"11" AND TargetFileName.keyword:*\\\\lsass.dmp*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/36d88494-1d43-4dc0-b3fa-35c8fea0ca9d <<EOF\n{\n  "metadata": {\n    "title": "CreateMiniDump Hacktool",\n    "description": "Detects the use of CreateMiniDump hack tool used to dump the LSASS process memory for credential extraction on the attacker\'s machine",\n    "tags": [\n      "attack.credential_access",\n      "attack.t1003"\n    ],\n    "query": "(winlog.event_data.Image.keyword:*\\\\\\\\CreateMiniDump.exe* OR winlog.event_data.Imphash:\\"4a07f944a83e8a7c2525efa35dd30e2f\\")"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.event_data.Image.keyword:*\\\\\\\\CreateMiniDump.exe* OR winlog.event_data.Imphash:\\"4a07f944a83e8a7c2525efa35dd30e2f\\")",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'CreateMiniDump Hacktool\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\ncurl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/36d88494-1d43-4dc0-b3fa-35c8fea0ca9d-2 <<EOF\n{\n  "metadata": {\n    "title": "CreateMiniDump Hacktool",\n    "description": "Detects the use of CreateMiniDump hack tool used to dump the LSASS process memory for credential extraction on the attacker\'s machine",\n    "tags": [\n      "attack.credential_access",\n      "attack.t1003"\n    ],\n    "query": "(winlog.channel:\\"Microsoft\\\\-Windows\\\\-Sysmon\\\\/Operational\\" AND winlog.event_id:\\"11\\" AND TargetFileName.keyword:*\\\\\\\\lsass.dmp*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.channel:\\"Microsoft\\\\-Windows\\\\-Sysmon\\\\/Operational\\" AND winlog.event_id:\\"11\\" AND TargetFileName.keyword:*\\\\\\\\lsass.dmp*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'CreateMiniDump Hacktool\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(Image.keyword:*\\\\CreateMiniDump.exe* OR Imphash:"4a07f944a83e8a7c2525efa35dd30e2f")\n(EventID:"11" AND TargetFileName.keyword:*\\\\lsass.dmp*)
```


### splunk
    
```
(Image="*\\\\CreateMiniDump.exe*" OR Imphash="4a07f944a83e8a7c2525efa35dd30e2f")\n(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="11" TargetFileName="*\\\\lsass.dmp*")
```


### logpoint
    
```
(Image="*\\\\CreateMiniDump.exe*" OR Imphash="4a07f944a83e8a7c2525efa35dd30e2f")\n(event_id="11" TargetFileName="*\\\\lsass.dmp*")
```


### grep
    
```
grep -P '^(?:.*(?:.*.*\\CreateMiniDump\\.exe.*|.*4a07f944a83e8a7c2525efa35dd30e2f))'\ngrep -P '^(?:.*(?=.*11)(?=.*.*\\lsass\\.dmp.*))'
```



