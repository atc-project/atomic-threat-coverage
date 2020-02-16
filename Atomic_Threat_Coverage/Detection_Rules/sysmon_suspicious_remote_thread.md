| Title                | Suspicious Remote Thread Created                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Offensive tradecraft is switching away from using APIs like "CreateRemoteThread", however, this is still largely observed in the wild. This rule aims to detect suspicious processes (those we would not expect to behave in this way like word.exe or outlook.exe) creating remote threads on other processes. It is a generalistic rule, but it should have a low FP ratio due to the selected range of processes.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1055: Process Injection](https://attack.mitre.org/techniques/T1055)</li></ul>  |
| Data Needed          | <ul><li>[DN_0012_8_windows_sysmon_CreateRemoteThread](../Data_Needed/DN_0012_8_windows_sysmon_CreateRemoteThread.md)</li></ul>  |
| Trigger              | <ul><li>[T1055: Process Injection](../Triggers/T1055.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[Personal research, statistical analysis](Personal research, statistical analysis)</li><li>[https://lolbas-project.github.io](https://lolbas-project.github.io)</li></ul>  |
| Author               | Perez Diego (@darkquassar), oscd.community |


## Detection Rules

### Sigma rule

```
title: Suspicious Remote Thread Created
id: 66d31e5f-52d6-40a4-9615-002d3789a119
description: Offensive tradecraft is switching away from using APIs like "CreateRemoteThread", however, this is still largely observed in the wild. This rule aims
    to detect suspicious processes (those we would not expect to behave in this way like word.exe or outlook.exe) creating remote threads on other processes. It is
    a generalistic rule, but it should have a low FP ratio due to the selected range of processes.
notes:
    - MonitoringHost.exe is a process that loads .NET CLR by default and thus a favorite for process injection for .NET in-memory offensive tools.
status: experimental
date: 27/10/2019
modified: 2019/11/13
author: Perez Diego (@darkquassar), oscd.community
references:
    - Personal research, statistical analysis
    - https://lolbas-project.github.io
logsource:
    product: windows
    service: sysmon
tags:
    - attack.privilege_escalation
    - attack.t1055
detection:
    selection: 
        EventID: 8
        SourceImage|endswith:
            - '\msbuild.exe'
            - '\powershell.exe'
            - '\word.exe'
            - '\excel.exe'
            - '\powerpnt.exe'
            - '\outlook.exe'
            - '\mspaint.exe'
            - '\winscp.exe'
            - '\w3wp.exe*'       
            - '\ping.exe'
            - '\taskhost.exe'
            - '\monitoringhost.exe'
            - '\wmic.exe'
            - '\find.exe'
            - '\findstr.exe'
            - '\smartscreen.exe'
            - '\gpupdate.exe'
            - '\iexplore.exe'
            - '\explorer.exe'
            - '\sapcimc.exe'
            - '\msiexec.exe'
            - '\git.exe'
            - '\vssvc.exe'
            - '\vssadmin.exe'
            - '\lync.exe'
            - '\python.exe'
            - '\provtool.exe'
            - '\robocopy.exe'
            - '\userinit.exe'
            - '\runonce.exe'
            - '\winlogon.exe'
            - '\defrag.exe'
            - '\bash.exe'
            - '\spoolsv.exe'
            - '\cvtres.exe'
            - '\esentutl.exe'
            - '\wscript.exe'
            - '\expand.exe'
            - '\forfiles.exe'
            - '\hh.exe'
            - '\installutil.exe'
            - '\makecab.exe'
            - '\mshta.exe'
            - '\regsvr32.exe'
            - '\schtasks.exe'
            - '\dnx.exe'
            - '\mDNSResponder.exe'
            - '\tstheme.exe'
    filter:
        SourceImage|contains: 'Visual Studio'
    condition: selection AND NOT filter
level: high
falsepositives:
    - Unknown

```





### es-qs
    
```
((EventID:"8" AND SourceImage.keyword:(*\\\\msbuild.exe OR *\\\\powershell.exe OR *\\\\word.exe OR *\\\\excel.exe OR *\\\\powerpnt.exe OR *\\\\outlook.exe OR *\\\\mspaint.exe OR *\\\\winscp.exe OR *\\\\w3wp.exe* OR *\\\\ping.exe OR *\\\\taskhost.exe OR *\\\\monitoringhost.exe OR *\\\\wmic.exe OR *\\\\find.exe OR *\\\\findstr.exe OR *\\\\smartscreen.exe OR *\\\\gpupdate.exe OR *\\\\iexplore.exe OR *\\\\explorer.exe OR *\\\\sapcimc.exe OR *\\\\msiexec.exe OR *\\\\git.exe OR *\\\\vssvc.exe OR *\\\\vssadmin.exe OR *\\\\lync.exe OR *\\\\python.exe OR *\\\\provtool.exe OR *\\\\robocopy.exe OR *\\\\userinit.exe OR *\\\\runonce.exe OR *\\\\winlogon.exe OR *\\\\defrag.exe OR *\\\\bash.exe OR *\\\\spoolsv.exe OR *\\\\cvtres.exe OR *\\\\esentutl.exe OR *\\\\wscript.exe OR *\\\\expand.exe OR *\\\\forfiles.exe OR *\\\\hh.exe OR *\\\\installutil.exe OR *\\\\makecab.exe OR *\\\\mshta.exe OR *\\\\regsvr32.exe OR *\\\\schtasks.exe OR *\\\\dnx.exe OR *\\\\mDNSResponder.exe OR *\\\\tstheme.exe)) AND (NOT (SourceImage.keyword:*Visual\\ Studio*)))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Suspicious-Remote-Thread-Created <<EOF\n{\n  "metadata": {\n    "title": "Suspicious Remote Thread Created",\n    "description": "Offensive tradecraft is switching away from using APIs like \\"CreateRemoteThread\\", however, this is still largely observed in the wild. This rule aims to detect suspicious processes (those we would not expect to behave in this way like word.exe or outlook.exe) creating remote threads on other processes. It is a generalistic rule, but it should have a low FP ratio due to the selected range of processes.",\n    "tags": [\n      "attack.privilege_escalation",\n      "attack.t1055"\n    ],\n    "query": "((EventID:\\"8\\" AND SourceImage.keyword:(*\\\\\\\\msbuild.exe OR *\\\\\\\\powershell.exe OR *\\\\\\\\word.exe OR *\\\\\\\\excel.exe OR *\\\\\\\\powerpnt.exe OR *\\\\\\\\outlook.exe OR *\\\\\\\\mspaint.exe OR *\\\\\\\\winscp.exe OR *\\\\\\\\w3wp.exe* OR *\\\\\\\\ping.exe OR *\\\\\\\\taskhost.exe OR *\\\\\\\\monitoringhost.exe OR *\\\\\\\\wmic.exe OR *\\\\\\\\find.exe OR *\\\\\\\\findstr.exe OR *\\\\\\\\smartscreen.exe OR *\\\\\\\\gpupdate.exe OR *\\\\\\\\iexplore.exe OR *\\\\\\\\explorer.exe OR *\\\\\\\\sapcimc.exe OR *\\\\\\\\msiexec.exe OR *\\\\\\\\git.exe OR *\\\\\\\\vssvc.exe OR *\\\\\\\\vssadmin.exe OR *\\\\\\\\lync.exe OR *\\\\\\\\python.exe OR *\\\\\\\\provtool.exe OR *\\\\\\\\robocopy.exe OR *\\\\\\\\userinit.exe OR *\\\\\\\\runonce.exe OR *\\\\\\\\winlogon.exe OR *\\\\\\\\defrag.exe OR *\\\\\\\\bash.exe OR *\\\\\\\\spoolsv.exe OR *\\\\\\\\cvtres.exe OR *\\\\\\\\esentutl.exe OR *\\\\\\\\wscript.exe OR *\\\\\\\\expand.exe OR *\\\\\\\\forfiles.exe OR *\\\\\\\\hh.exe OR *\\\\\\\\installutil.exe OR *\\\\\\\\makecab.exe OR *\\\\\\\\mshta.exe OR *\\\\\\\\regsvr32.exe OR *\\\\\\\\schtasks.exe OR *\\\\\\\\dnx.exe OR *\\\\\\\\mDNSResponder.exe OR *\\\\\\\\tstheme.exe)) AND (NOT (SourceImage.keyword:*Visual\\\\ Studio*)))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((EventID:\\"8\\" AND SourceImage.keyword:(*\\\\\\\\msbuild.exe OR *\\\\\\\\powershell.exe OR *\\\\\\\\word.exe OR *\\\\\\\\excel.exe OR *\\\\\\\\powerpnt.exe OR *\\\\\\\\outlook.exe OR *\\\\\\\\mspaint.exe OR *\\\\\\\\winscp.exe OR *\\\\\\\\w3wp.exe* OR *\\\\\\\\ping.exe OR *\\\\\\\\taskhost.exe OR *\\\\\\\\monitoringhost.exe OR *\\\\\\\\wmic.exe OR *\\\\\\\\find.exe OR *\\\\\\\\findstr.exe OR *\\\\\\\\smartscreen.exe OR *\\\\\\\\gpupdate.exe OR *\\\\\\\\iexplore.exe OR *\\\\\\\\explorer.exe OR *\\\\\\\\sapcimc.exe OR *\\\\\\\\msiexec.exe OR *\\\\\\\\git.exe OR *\\\\\\\\vssvc.exe OR *\\\\\\\\vssadmin.exe OR *\\\\\\\\lync.exe OR *\\\\\\\\python.exe OR *\\\\\\\\provtool.exe OR *\\\\\\\\robocopy.exe OR *\\\\\\\\userinit.exe OR *\\\\\\\\runonce.exe OR *\\\\\\\\winlogon.exe OR *\\\\\\\\defrag.exe OR *\\\\\\\\bash.exe OR *\\\\\\\\spoolsv.exe OR *\\\\\\\\cvtres.exe OR *\\\\\\\\esentutl.exe OR *\\\\\\\\wscript.exe OR *\\\\\\\\expand.exe OR *\\\\\\\\forfiles.exe OR *\\\\\\\\hh.exe OR *\\\\\\\\installutil.exe OR *\\\\\\\\makecab.exe OR *\\\\\\\\mshta.exe OR *\\\\\\\\regsvr32.exe OR *\\\\\\\\schtasks.exe OR *\\\\\\\\dnx.exe OR *\\\\\\\\mDNSResponder.exe OR *\\\\\\\\tstheme.exe)) AND (NOT (SourceImage.keyword:*Visual\\\\ Studio*)))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Suspicious Remote Thread Created\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((EventID:"8" AND SourceImage.keyword:(*\\\\msbuild.exe *\\\\powershell.exe *\\\\word.exe *\\\\excel.exe *\\\\powerpnt.exe *\\\\outlook.exe *\\\\mspaint.exe *\\\\winscp.exe *\\\\w3wp.exe* *\\\\ping.exe *\\\\taskhost.exe *\\\\monitoringhost.exe *\\\\wmic.exe *\\\\find.exe *\\\\findstr.exe *\\\\smartscreen.exe *\\\\gpupdate.exe *\\\\iexplore.exe *\\\\explorer.exe *\\\\sapcimc.exe *\\\\msiexec.exe *\\\\git.exe *\\\\vssvc.exe *\\\\vssadmin.exe *\\\\lync.exe *\\\\python.exe *\\\\provtool.exe *\\\\robocopy.exe *\\\\userinit.exe *\\\\runonce.exe *\\\\winlogon.exe *\\\\defrag.exe *\\\\bash.exe *\\\\spoolsv.exe *\\\\cvtres.exe *\\\\esentutl.exe *\\\\wscript.exe *\\\\expand.exe *\\\\forfiles.exe *\\\\hh.exe *\\\\installutil.exe *\\\\makecab.exe *\\\\mshta.exe *\\\\regsvr32.exe *\\\\schtasks.exe *\\\\dnx.exe *\\\\mDNSResponder.exe *\\\\tstheme.exe)) AND (NOT (SourceImage.keyword:*Visual Studio*)))
```


### splunk
    
```
((EventID="8" (SourceImage="*\\\\msbuild.exe" OR SourceImage="*\\\\powershell.exe" OR SourceImage="*\\\\word.exe" OR SourceImage="*\\\\excel.exe" OR SourceImage="*\\\\powerpnt.exe" OR SourceImage="*\\\\outlook.exe" OR SourceImage="*\\\\mspaint.exe" OR SourceImage="*\\\\winscp.exe" OR SourceImage="*\\\\w3wp.exe*" OR SourceImage="*\\\\ping.exe" OR SourceImage="*\\\\taskhost.exe" OR SourceImage="*\\\\monitoringhost.exe" OR SourceImage="*\\\\wmic.exe" OR SourceImage="*\\\\find.exe" OR SourceImage="*\\\\findstr.exe" OR SourceImage="*\\\\smartscreen.exe" OR SourceImage="*\\\\gpupdate.exe" OR SourceImage="*\\\\iexplore.exe" OR SourceImage="*\\\\explorer.exe" OR SourceImage="*\\\\sapcimc.exe" OR SourceImage="*\\\\msiexec.exe" OR SourceImage="*\\\\git.exe" OR SourceImage="*\\\\vssvc.exe" OR SourceImage="*\\\\vssadmin.exe" OR SourceImage="*\\\\lync.exe" OR SourceImage="*\\\\python.exe" OR SourceImage="*\\\\provtool.exe" OR SourceImage="*\\\\robocopy.exe" OR SourceImage="*\\\\userinit.exe" OR SourceImage="*\\\\runonce.exe" OR SourceImage="*\\\\winlogon.exe" OR SourceImage="*\\\\defrag.exe" OR SourceImage="*\\\\bash.exe" OR SourceImage="*\\\\spoolsv.exe" OR SourceImage="*\\\\cvtres.exe" OR SourceImage="*\\\\esentutl.exe" OR SourceImage="*\\\\wscript.exe" OR SourceImage="*\\\\expand.exe" OR SourceImage="*\\\\forfiles.exe" OR SourceImage="*\\\\hh.exe" OR SourceImage="*\\\\installutil.exe" OR SourceImage="*\\\\makecab.exe" OR SourceImage="*\\\\mshta.exe" OR SourceImage="*\\\\regsvr32.exe" OR SourceImage="*\\\\schtasks.exe" OR SourceImage="*\\\\dnx.exe" OR SourceImage="*\\\\mDNSResponder.exe" OR SourceImage="*\\\\tstheme.exe")) NOT (SourceImage="*Visual Studio*"))
```


### logpoint
    
```
((event_id="8" SourceImage IN ["*\\\\msbuild.exe", "*\\\\powershell.exe", "*\\\\word.exe", "*\\\\excel.exe", "*\\\\powerpnt.exe", "*\\\\outlook.exe", "*\\\\mspaint.exe", "*\\\\winscp.exe", "*\\\\w3wp.exe*", "*\\\\ping.exe", "*\\\\taskhost.exe", "*\\\\monitoringhost.exe", "*\\\\wmic.exe", "*\\\\find.exe", "*\\\\findstr.exe", "*\\\\smartscreen.exe", "*\\\\gpupdate.exe", "*\\\\iexplore.exe", "*\\\\explorer.exe", "*\\\\sapcimc.exe", "*\\\\msiexec.exe", "*\\\\git.exe", "*\\\\vssvc.exe", "*\\\\vssadmin.exe", "*\\\\lync.exe", "*\\\\python.exe", "*\\\\provtool.exe", "*\\\\robocopy.exe", "*\\\\userinit.exe", "*\\\\runonce.exe", "*\\\\winlogon.exe", "*\\\\defrag.exe", "*\\\\bash.exe", "*\\\\spoolsv.exe", "*\\\\cvtres.exe", "*\\\\esentutl.exe", "*\\\\wscript.exe", "*\\\\expand.exe", "*\\\\forfiles.exe", "*\\\\hh.exe", "*\\\\installutil.exe", "*\\\\makecab.exe", "*\\\\mshta.exe", "*\\\\regsvr32.exe", "*\\\\schtasks.exe", "*\\\\dnx.exe", "*\\\\mDNSResponder.exe", "*\\\\tstheme.exe"])  -(SourceImage="*Visual Studio*"))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*8)(?=.*(?:.*.*\\msbuild\\.exe|.*.*\\powershell\\.exe|.*.*\\word\\.exe|.*.*\\excel\\.exe|.*.*\\powerpnt\\.exe|.*.*\\outlook\\.exe|.*.*\\mspaint\\.exe|.*.*\\winscp\\.exe|.*.*\\w3wp\\.exe.*|.*.*\\ping\\.exe|.*.*\\taskhost\\.exe|.*.*\\monitoringhost\\.exe|.*.*\\wmic\\.exe|.*.*\\find\\.exe|.*.*\\findstr\\.exe|.*.*\\smartscreen\\.exe|.*.*\\gpupdate\\.exe|.*.*\\iexplore\\.exe|.*.*\\explorer\\.exe|.*.*\\sapcimc\\.exe|.*.*\\msiexec\\.exe|.*.*\\git\\.exe|.*.*\\vssvc\\.exe|.*.*\\vssadmin\\.exe|.*.*\\lync\\.exe|.*.*\\python\\.exe|.*.*\\provtool\\.exe|.*.*\\robocopy\\.exe|.*.*\\userinit\\.exe|.*.*\\runonce\\.exe|.*.*\\winlogon\\.exe|.*.*\\defrag\\.exe|.*.*\\bash\\.exe|.*.*\\spoolsv\\.exe|.*.*\\cvtres\\.exe|.*.*\\esentutl\\.exe|.*.*\\wscript\\.exe|.*.*\\expand\\.exe|.*.*\\forfiles\\.exe|.*.*\\hh\\.exe|.*.*\\installutil\\.exe|.*.*\\makecab\\.exe|.*.*\\mshta\\.exe|.*.*\\regsvr32\\.exe|.*.*\\schtasks\\.exe|.*.*\\dnx\\.exe|.*.*\\mDNSResponder\\.exe|.*.*\\tstheme\\.exe))))(?=.*(?!.*(?:.*(?=.*.*Visual Studio.*)))))'
```



