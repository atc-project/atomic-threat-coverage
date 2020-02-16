| Title                | Cred dump tools dropped files                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Files with well-known filenames (parts of credential dump software or files produced by them) creation                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1003: Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| Data Needed          | <ul><li>[DN_0015_11_windows_sysmon_FileCreate](../Data_Needed/DN_0015_11_windows_sysmon_FileCreate.md)</li></ul>  |
| Trigger              | <ul><li>[T1003: Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Legitimate Administrator using tool for password recovery</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment](https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment)</li></ul>  |
| Author               | Teymur Kheirkhabarov, oscd.community |


## Detection Rules

### Sigma rule

```
title: Cred dump tools dropped files
id: 8fbf3271-1ef6-4e94-8210-03c2317947f6
description: Files with well-known filenames (parts of credential dump software or files produced by them) creation
author: Teymur Kheirkhabarov, oscd.community
date: 2019/11/01
modified: 2019/11/13
references:
    - https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment
tags:
    - attack.credential_access
    - attack.t1003
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 11
        TargetFilename|contains: 
            - '\pwdump'
            - '\kirbi'
            - '\pwhashes'
            - '\wce_ccache'
            - '\wce_krbtkts'
            - '\fgdump-log'
        TargetFilename|endswith: 
            - '\test.pwd'
            - '\lsremora64.dll'
            - '\lsremora.dll'
            - '\fgexec.exe'
            - '\wceaux.dll'
            - '\SAM.out'
            - '\SECURITY.out'
            - '\SYSTEM.out'
            - '\NTDS.out'
            - '\DumpExt.dll'
            - '\DumpSvc.exe'
            - '\cachedump64.exe'
            - '\cachedump.exe'
            - '\pstgdump.exe'
            - '\servpw.exe'
            - '\servpw64.exe'
            - '\pwdump.exe'
    condition: selection
falsepositives:
    - Legitimate Administrator using tool for password recovery
level: medium
status: experimental

```





### es-qs
    
```
(EventID:"11" AND TargetFilename.keyword:(*\\\\pwdump* OR *\\\\kirbi* OR *\\\\pwhashes* OR *\\\\wce_ccache* OR *\\\\wce_krbtkts* OR *\\\\fgdump\\-log*) AND TargetFilename.keyword:(*\\\\test.pwd OR *\\\\lsremora64.dll OR *\\\\lsremora.dll OR *\\\\fgexec.exe OR *\\\\wceaux.dll OR *\\\\SAM.out OR *\\\\SECURITY.out OR *\\\\SYSTEM.out OR *\\\\NTDS.out OR *\\\\DumpExt.dll OR *\\\\DumpSvc.exe OR *\\\\cachedump64.exe OR *\\\\cachedump.exe OR *\\\\pstgdump.exe OR *\\\\servpw.exe OR *\\\\servpw64.exe OR *\\\\pwdump.exe))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Cred-dump-tools-dropped-files <<EOF\n{\n  "metadata": {\n    "title": "Cred dump tools dropped files",\n    "description": "Files with well-known filenames (parts of credential dump software or files produced by them) creation",\n    "tags": [\n      "attack.credential_access",\n      "attack.t1003"\n    ],\n    "query": "(EventID:\\"11\\" AND TargetFilename.keyword:(*\\\\\\\\pwdump* OR *\\\\\\\\kirbi* OR *\\\\\\\\pwhashes* OR *\\\\\\\\wce_ccache* OR *\\\\\\\\wce_krbtkts* OR *\\\\\\\\fgdump\\\\-log*) AND TargetFilename.keyword:(*\\\\\\\\test.pwd OR *\\\\\\\\lsremora64.dll OR *\\\\\\\\lsremora.dll OR *\\\\\\\\fgexec.exe OR *\\\\\\\\wceaux.dll OR *\\\\\\\\SAM.out OR *\\\\\\\\SECURITY.out OR *\\\\\\\\SYSTEM.out OR *\\\\\\\\NTDS.out OR *\\\\\\\\DumpExt.dll OR *\\\\\\\\DumpSvc.exe OR *\\\\\\\\cachedump64.exe OR *\\\\\\\\cachedump.exe OR *\\\\\\\\pstgdump.exe OR *\\\\\\\\servpw.exe OR *\\\\\\\\servpw64.exe OR *\\\\\\\\pwdump.exe))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"11\\" AND TargetFilename.keyword:(*\\\\\\\\pwdump* OR *\\\\\\\\kirbi* OR *\\\\\\\\pwhashes* OR *\\\\\\\\wce_ccache* OR *\\\\\\\\wce_krbtkts* OR *\\\\\\\\fgdump\\\\-log*) AND TargetFilename.keyword:(*\\\\\\\\test.pwd OR *\\\\\\\\lsremora64.dll OR *\\\\\\\\lsremora.dll OR *\\\\\\\\fgexec.exe OR *\\\\\\\\wceaux.dll OR *\\\\\\\\SAM.out OR *\\\\\\\\SECURITY.out OR *\\\\\\\\SYSTEM.out OR *\\\\\\\\NTDS.out OR *\\\\\\\\DumpExt.dll OR *\\\\\\\\DumpSvc.exe OR *\\\\\\\\cachedump64.exe OR *\\\\\\\\cachedump.exe OR *\\\\\\\\pstgdump.exe OR *\\\\\\\\servpw.exe OR *\\\\\\\\servpw64.exe OR *\\\\\\\\pwdump.exe))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Cred dump tools dropped files\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"11" AND TargetFilename.keyword:(*\\\\pwdump* *\\\\kirbi* *\\\\pwhashes* *\\\\wce_ccache* *\\\\wce_krbtkts* *\\\\fgdump\\-log*) AND TargetFilename.keyword:(*\\\\test.pwd *\\\\lsremora64.dll *\\\\lsremora.dll *\\\\fgexec.exe *\\\\wceaux.dll *\\\\SAM.out *\\\\SECURITY.out *\\\\SYSTEM.out *\\\\NTDS.out *\\\\DumpExt.dll *\\\\DumpSvc.exe *\\\\cachedump64.exe *\\\\cachedump.exe *\\\\pstgdump.exe *\\\\servpw.exe *\\\\servpw64.exe *\\\\pwdump.exe))
```


### splunk
    
```
(EventID="11" (TargetFilename="*\\\\pwdump*" OR TargetFilename="*\\\\kirbi*" OR TargetFilename="*\\\\pwhashes*" OR TargetFilename="*\\\\wce_ccache*" OR TargetFilename="*\\\\wce_krbtkts*" OR TargetFilename="*\\\\fgdump-log*") (TargetFilename="*\\\\test.pwd" OR TargetFilename="*\\\\lsremora64.dll" OR TargetFilename="*\\\\lsremora.dll" OR TargetFilename="*\\\\fgexec.exe" OR TargetFilename="*\\\\wceaux.dll" OR TargetFilename="*\\\\SAM.out" OR TargetFilename="*\\\\SECURITY.out" OR TargetFilename="*\\\\SYSTEM.out" OR TargetFilename="*\\\\NTDS.out" OR TargetFilename="*\\\\DumpExt.dll" OR TargetFilename="*\\\\DumpSvc.exe" OR TargetFilename="*\\\\cachedump64.exe" OR TargetFilename="*\\\\cachedump.exe" OR TargetFilename="*\\\\pstgdump.exe" OR TargetFilename="*\\\\servpw.exe" OR TargetFilename="*\\\\servpw64.exe" OR TargetFilename="*\\\\pwdump.exe"))
```


### logpoint
    
```
(event_id="11" TargetFilename IN ["*\\\\pwdump*", "*\\\\kirbi*", "*\\\\pwhashes*", "*\\\\wce_ccache*", "*\\\\wce_krbtkts*", "*\\\\fgdump-log*"] TargetFilename IN ["*\\\\test.pwd", "*\\\\lsremora64.dll", "*\\\\lsremora.dll", "*\\\\fgexec.exe", "*\\\\wceaux.dll", "*\\\\SAM.out", "*\\\\SECURITY.out", "*\\\\SYSTEM.out", "*\\\\NTDS.out", "*\\\\DumpExt.dll", "*\\\\DumpSvc.exe", "*\\\\cachedump64.exe", "*\\\\cachedump.exe", "*\\\\pstgdump.exe", "*\\\\servpw.exe", "*\\\\servpw64.exe", "*\\\\pwdump.exe"])
```


### grep
    
```
grep -P '^(?:.*(?=.*11)(?=.*(?:.*.*\\pwdump.*|.*.*\\kirbi.*|.*.*\\pwhashes.*|.*.*\\wce_ccache.*|.*.*\\wce_krbtkts.*|.*.*\\fgdump-log.*))(?=.*(?:.*.*\\test\\.pwd|.*.*\\lsremora64\\.dll|.*.*\\lsremora\\.dll|.*.*\\fgexec\\.exe|.*.*\\wceaux\\.dll|.*.*\\SAM\\.out|.*.*\\SECURITY\\.out|.*.*\\SYSTEM\\.out|.*.*\\NTDS\\.out|.*.*\\DumpExt\\.dll|.*.*\\DumpSvc\\.exe|.*.*\\cachedump64\\.exe|.*.*\\cachedump\\.exe|.*.*\\pstgdump\\.exe|.*.*\\servpw\\.exe|.*.*\\servpw64\\.exe|.*.*\\pwdump\\.exe)))'
```



