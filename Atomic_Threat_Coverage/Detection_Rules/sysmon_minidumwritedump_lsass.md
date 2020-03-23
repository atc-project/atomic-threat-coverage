| Title                | Dumping Lsass.exe Memory with MiniDumpWriteDump API                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects the use of MiniDumpWriteDump API for dumping lsass.exe memory in a stealth way. Tools like ProcessHacker and some attacker tradecract use this API found in dbghelp.dll or dbgcore.dll. As an example, SilentTrynity C2 Framework has a module that leverages this API to dump the contents of Lsass.exe and transfer it over the network back to the attacker's machine.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1003: Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| Data Needed          | <ul><li>[DN_0011_7_windows_sysmon_image_loaded](../Data_Needed/DN_0011_7_windows_sysmon_image_loaded.md)</li></ul>  |
| Trigger              | <ul><li>[T1003: Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| Severity Level       | critical |
| False Positives      | <ul><li>Penetration tests</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://docs.microsoft.com/en-us/windows/win32/api/minidumpapiset/nf-minidumpapiset-minidumpwritedump](https://docs.microsoft.com/en-us/windows/win32/api/minidumpapiset/nf-minidumpapiset-minidumpwritedump)</li><li>[https://www.pinvoke.net/default.aspx/dbghelp/MiniDumpWriteDump.html](https://www.pinvoke.net/default.aspx/dbghelp/MiniDumpWriteDump.html)</li><li>[https://medium.com/@fsx30/bypass-edrs-memory-protection-introduction-to-hooking-2efb21acffd6](https://medium.com/@fsx30/bypass-edrs-memory-protection-introduction-to-hooking-2efb21acffd6)</li></ul>  |
| Author               | Perez Diego (@darkquassar), oscd.community |


## Detection Rules

### Sigma rule

```
title: Dumping Lsass.exe Memory with MiniDumpWriteDump API
id: dd5ab153-beaa-4315-9647-65abc5f71541
status: experimental
description: Detects the use of MiniDumpWriteDump API for dumping lsass.exe memory in a stealth way. Tools like ProcessHacker and some attacker tradecract use this
    API found in dbghelp.dll or dbgcore.dll. As an example, SilentTrynity C2 Framework has a module that leverages this API to dump the contents of Lsass.exe and
    transfer it over the network back to the attacker's machine.
date: 27/10/2019
modified: 2019/11/13
author: Perez Diego (@darkquassar), oscd.community
references:
    - https://docs.microsoft.com/en-us/windows/win32/api/minidumpapiset/nf-minidumpapiset-minidumpwritedump
    - https://www.pinvoke.net/default.aspx/dbghelp/MiniDumpWriteDump.html
    - https://medium.com/@fsx30/bypass-edrs-memory-protection-introduction-to-hooking-2efb21acffd6
tags:
    - attack.credential_access
    - attack.t1003
logsource:
    product: windows
    service: sysmon
detection:
    signedprocess:
        EventID: 7
        ImageLoaded|endswith:
            - '\dbghelp.dll'
            - '\dbgcore.dll'
        Image|endswith: 
            - '\msbuild.exe'
            - '\cmd.exe'
            - '\svchost.exe'
            - '\rundll32.exe'
            - '\powershell.exe'
            - '\word.exe'
            - '\excel.exe'
            - '\powerpnt.exe'
            - '\outlook.exe'
            - '\monitoringhost.exe'
            - '\wmic.exe'
            - '\msiexec.exe'
            - '\bash.exe'
            - '\wscript.exe'
            - '\cscript.exe'
            - '\mshta.exe'
            - '\regsvr32.exe'
            - '\schtasks.exe'
            - '\dnx.exe'
            - '\regsvcs.exe'
            - '\sc.exe'
            - '\scriptrunner.exe'
    unsignedprocess:
        EventID: 7
        ImageLoaded|endswith:
            - '\dbghelp.dll'
            - '\dbgcore.dll'
        Signed: "FALSE"
    filter:
        Image|contains: 'Visual Studio'
    condition: (signedprocess AND NOT filter) OR (unsignedprocess AND NOT filter)
fields:
    - ComputerName
    - User
    - Image
    - ImageLoaded
falsepositives:
    - Penetration tests
level: critical

```





### es-qs
    
```
(((EventID:"7" AND ImageLoaded.keyword:(*\\\\dbghelp.dll OR *\\\\dbgcore.dll) AND Image.keyword:(*\\\\msbuild.exe OR *\\\\cmd.exe OR *\\\\svchost.exe OR *\\\\rundll32.exe OR *\\\\powershell.exe OR *\\\\word.exe OR *\\\\excel.exe OR *\\\\powerpnt.exe OR *\\\\outlook.exe OR *\\\\monitoringhost.exe OR *\\\\wmic.exe OR *\\\\msiexec.exe OR *\\\\bash.exe OR *\\\\wscript.exe OR *\\\\cscript.exe OR *\\\\mshta.exe OR *\\\\regsvr32.exe OR *\\\\schtasks.exe OR *\\\\dnx.exe OR *\\\\regsvcs.exe OR *\\\\sc.exe OR *\\\\scriptrunner.exe)) AND (NOT (Image.keyword:*Visual\\ Studio*))) OR ((EventID:"7" AND ImageLoaded.keyword:(*\\\\dbghelp.dll OR *\\\\dbgcore.dll) AND Signed:"FALSE") AND (NOT (Image.keyword:*Visual\\ Studio*))))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/dd5ab153-beaa-4315-9647-65abc5f71541 <<EOF\n{\n  "metadata": {\n    "title": "Dumping Lsass.exe Memory with MiniDumpWriteDump API",\n    "description": "Detects the use of MiniDumpWriteDump API for dumping lsass.exe memory in a stealth way. Tools like ProcessHacker and some attacker tradecract use this API found in dbghelp.dll or dbgcore.dll. As an example, SilentTrynity C2 Framework has a module that leverages this API to dump the contents of Lsass.exe and transfer it over the network back to the attacker\'s machine.",\n    "tags": [\n      "attack.credential_access",\n      "attack.t1003"\n    ],\n    "query": "(((EventID:\\"7\\" AND ImageLoaded.keyword:(*\\\\\\\\dbghelp.dll OR *\\\\\\\\dbgcore.dll) AND Image.keyword:(*\\\\\\\\msbuild.exe OR *\\\\\\\\cmd.exe OR *\\\\\\\\svchost.exe OR *\\\\\\\\rundll32.exe OR *\\\\\\\\powershell.exe OR *\\\\\\\\word.exe OR *\\\\\\\\excel.exe OR *\\\\\\\\powerpnt.exe OR *\\\\\\\\outlook.exe OR *\\\\\\\\monitoringhost.exe OR *\\\\\\\\wmic.exe OR *\\\\\\\\msiexec.exe OR *\\\\\\\\bash.exe OR *\\\\\\\\wscript.exe OR *\\\\\\\\cscript.exe OR *\\\\\\\\mshta.exe OR *\\\\\\\\regsvr32.exe OR *\\\\\\\\schtasks.exe OR *\\\\\\\\dnx.exe OR *\\\\\\\\regsvcs.exe OR *\\\\\\\\sc.exe OR *\\\\\\\\scriptrunner.exe)) AND (NOT (Image.keyword:*Visual\\\\ Studio*))) OR ((EventID:\\"7\\" AND ImageLoaded.keyword:(*\\\\\\\\dbghelp.dll OR *\\\\\\\\dbgcore.dll) AND Signed:\\"FALSE\\") AND (NOT (Image.keyword:*Visual\\\\ Studio*))))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(((EventID:\\"7\\" AND ImageLoaded.keyword:(*\\\\\\\\dbghelp.dll OR *\\\\\\\\dbgcore.dll) AND Image.keyword:(*\\\\\\\\msbuild.exe OR *\\\\\\\\cmd.exe OR *\\\\\\\\svchost.exe OR *\\\\\\\\rundll32.exe OR *\\\\\\\\powershell.exe OR *\\\\\\\\word.exe OR *\\\\\\\\excel.exe OR *\\\\\\\\powerpnt.exe OR *\\\\\\\\outlook.exe OR *\\\\\\\\monitoringhost.exe OR *\\\\\\\\wmic.exe OR *\\\\\\\\msiexec.exe OR *\\\\\\\\bash.exe OR *\\\\\\\\wscript.exe OR *\\\\\\\\cscript.exe OR *\\\\\\\\mshta.exe OR *\\\\\\\\regsvr32.exe OR *\\\\\\\\schtasks.exe OR *\\\\\\\\dnx.exe OR *\\\\\\\\regsvcs.exe OR *\\\\\\\\sc.exe OR *\\\\\\\\scriptrunner.exe)) AND (NOT (Image.keyword:*Visual\\\\ Studio*))) OR ((EventID:\\"7\\" AND ImageLoaded.keyword:(*\\\\\\\\dbghelp.dll OR *\\\\\\\\dbgcore.dll) AND Signed:\\"FALSE\\") AND (NOT (Image.keyword:*Visual\\\\ Studio*))))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Dumping Lsass.exe Memory with MiniDumpWriteDump API\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\nComputerName = {{_source.ComputerName}}\\n        User = {{_source.User}}\\n       Image = {{_source.Image}}\\n ImageLoaded = {{_source.ImageLoaded}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(((EventID:"7" AND ImageLoaded.keyword:(*\\\\dbghelp.dll *\\\\dbgcore.dll) AND Image.keyword:(*\\\\msbuild.exe *\\\\cmd.exe *\\\\svchost.exe *\\\\rundll32.exe *\\\\powershell.exe *\\\\word.exe *\\\\excel.exe *\\\\powerpnt.exe *\\\\outlook.exe *\\\\monitoringhost.exe *\\\\wmic.exe *\\\\msiexec.exe *\\\\bash.exe *\\\\wscript.exe *\\\\cscript.exe *\\\\mshta.exe *\\\\regsvr32.exe *\\\\schtasks.exe *\\\\dnx.exe *\\\\regsvcs.exe *\\\\sc.exe *\\\\scriptrunner.exe)) AND (NOT (Image.keyword:*Visual Studio*))) OR ((EventID:"7" AND ImageLoaded.keyword:(*\\\\dbghelp.dll *\\\\dbgcore.dll) AND Signed:"FALSE") AND (NOT (Image.keyword:*Visual Studio*))))
```


### splunk
    
```
(((EventID="7" (ImageLoaded="*\\\\dbghelp.dll" OR ImageLoaded="*\\\\dbgcore.dll") (Image="*\\\\msbuild.exe" OR Image="*\\\\cmd.exe" OR Image="*\\\\svchost.exe" OR Image="*\\\\rundll32.exe" OR Image="*\\\\powershell.exe" OR Image="*\\\\word.exe" OR Image="*\\\\excel.exe" OR Image="*\\\\powerpnt.exe" OR Image="*\\\\outlook.exe" OR Image="*\\\\monitoringhost.exe" OR Image="*\\\\wmic.exe" OR Image="*\\\\msiexec.exe" OR Image="*\\\\bash.exe" OR Image="*\\\\wscript.exe" OR Image="*\\\\cscript.exe" OR Image="*\\\\mshta.exe" OR Image="*\\\\regsvr32.exe" OR Image="*\\\\schtasks.exe" OR Image="*\\\\dnx.exe" OR Image="*\\\\regsvcs.exe" OR Image="*\\\\sc.exe" OR Image="*\\\\scriptrunner.exe")) NOT (Image="*Visual Studio*")) OR ((EventID="7" (ImageLoaded="*\\\\dbghelp.dll" OR ImageLoaded="*\\\\dbgcore.dll") Signed="FALSE") NOT (Image="*Visual Studio*"))) | table ComputerName,User,Image,ImageLoaded
```


### logpoint
    
```
(((event_id="7" ImageLoaded IN ["*\\\\dbghelp.dll", "*\\\\dbgcore.dll"] Image IN ["*\\\\msbuild.exe", "*\\\\cmd.exe", "*\\\\svchost.exe", "*\\\\rundll32.exe", "*\\\\powershell.exe", "*\\\\word.exe", "*\\\\excel.exe", "*\\\\powerpnt.exe", "*\\\\outlook.exe", "*\\\\monitoringhost.exe", "*\\\\wmic.exe", "*\\\\msiexec.exe", "*\\\\bash.exe", "*\\\\wscript.exe", "*\\\\cscript.exe", "*\\\\mshta.exe", "*\\\\regsvr32.exe", "*\\\\schtasks.exe", "*\\\\dnx.exe", "*\\\\regsvcs.exe", "*\\\\sc.exe", "*\\\\scriptrunner.exe"])  -(Image="*Visual Studio*")) OR ((event_id="7" ImageLoaded IN ["*\\\\dbghelp.dll", "*\\\\dbgcore.dll"] Signed="FALSE")  -(Image="*Visual Studio*")))
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*(?=.*(?:.*(?=.*7)(?=.*(?:.*.*\\dbghelp\\.dll|.*.*\\dbgcore\\.dll))(?=.*(?:.*.*\\msbuild\\.exe|.*.*\\cmd\\.exe|.*.*\\svchost\\.exe|.*.*\\rundll32\\.exe|.*.*\\powershell\\.exe|.*.*\\word\\.exe|.*.*\\excel\\.exe|.*.*\\powerpnt\\.exe|.*.*\\outlook\\.exe|.*.*\\monitoringhost\\.exe|.*.*\\wmic\\.exe|.*.*\\msiexec\\.exe|.*.*\\bash\\.exe|.*.*\\wscript\\.exe|.*.*\\cscript\\.exe|.*.*\\mshta\\.exe|.*.*\\regsvr32\\.exe|.*.*\\schtasks\\.exe|.*.*\\dnx\\.exe|.*.*\\regsvcs\\.exe|.*.*\\sc\\.exe|.*.*\\scriptrunner\\.exe))))(?=.*(?!.*(?:.*(?=.*.*Visual Studio.*)))))|.*(?:.*(?=.*(?:.*(?=.*7)(?=.*(?:.*.*\\dbghelp\\.dll|.*.*\\dbgcore\\.dll))(?=.*FALSE)))(?=.*(?!.*(?:.*(?=.*.*Visual Studio.*)))))))'
```



