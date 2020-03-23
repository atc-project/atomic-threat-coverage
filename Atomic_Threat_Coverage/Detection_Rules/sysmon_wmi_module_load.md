| Title                | WMI Modules Loaded                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects non wmiprvse loading WMI modules                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1047: Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047)</li></ul>  |
| Data Needed          | <ul><li>[DN_0011_7_windows_sysmon_image_loaded](../Data_Needed/DN_0011_7_windows_sysmon_image_loaded.md)</li></ul>  |
| Trigger              | <ul><li>[T1047: Windows Management Instrumentation](../Triggers/T1047.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/02_execution/T1047_windows_management_instrumentation/wmi_wmi_module_load.md](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/02_execution/T1047_windows_management_instrumentation/wmi_wmi_module_load.md)</li></ul>  |
| Author               | Roberto Rodriguez @Cyb3rWard0g |


## Detection Rules

### Sigma rule

```
title: WMI Modules Loaded
id: 671bb7e3-a020-4824-a00e-2ee5b55f385e
description: Detects non wmiprvse loading WMI modules
status: experimental
date: 2019/08/10
modified: 2019/11/10
author: Roberto Rodriguez @Cyb3rWard0g
references:
    - https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/02_execution/T1047_windows_management_instrumentation/wmi_wmi_module_load.md
tags:
    - attack.execution
    - attack.t1047
logsource:
    product: windows
    service: sysmon
detection:
    selection: 
        EventID: 7
        ImageLoaded|endswith:
            - '\wmiclnt.dll'
            - '\WmiApRpl.dll'
            - '\wmiprov.dll'
            - '\wmiutils.dll'
            - '\wbemcomn.dll'
            - '\wbemprox.dll'
            - '\WMINet_Utils.dll'
            - '\wbemsvc.dll'
            - '\fastprox.dll'
    filter:
        Image|endswith:
            - '\WmiPrvSe.exe'
            - '\WmiAPsrv.exe'
            - '\svchost.exe'
    condition: selection and not filter
fields:
    - ComputerName
    - User
    - Image
    - ImageLoaded
falsepositives:
    - Unknown
level: high

```





### es-qs
    
```
((EventID:"7" AND ImageLoaded.keyword:(*\\\\wmiclnt.dll OR *\\\\WmiApRpl.dll OR *\\\\wmiprov.dll OR *\\\\wmiutils.dll OR *\\\\wbemcomn.dll OR *\\\\wbemprox.dll OR *\\\\WMINet_Utils.dll OR *\\\\wbemsvc.dll OR *\\\\fastprox.dll)) AND (NOT (Image.keyword:(*\\\\WmiPrvSe.exe OR *\\\\WmiAPsrv.exe OR *\\\\svchost.exe))))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/671bb7e3-a020-4824-a00e-2ee5b55f385e <<EOF\n{\n  "metadata": {\n    "title": "WMI Modules Loaded",\n    "description": "Detects non wmiprvse loading WMI modules",\n    "tags": [\n      "attack.execution",\n      "attack.t1047"\n    ],\n    "query": "((EventID:\\"7\\" AND ImageLoaded.keyword:(*\\\\\\\\wmiclnt.dll OR *\\\\\\\\WmiApRpl.dll OR *\\\\\\\\wmiprov.dll OR *\\\\\\\\wmiutils.dll OR *\\\\\\\\wbemcomn.dll OR *\\\\\\\\wbemprox.dll OR *\\\\\\\\WMINet_Utils.dll OR *\\\\\\\\wbemsvc.dll OR *\\\\\\\\fastprox.dll)) AND (NOT (Image.keyword:(*\\\\\\\\WmiPrvSe.exe OR *\\\\\\\\WmiAPsrv.exe OR *\\\\\\\\svchost.exe))))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((EventID:\\"7\\" AND ImageLoaded.keyword:(*\\\\\\\\wmiclnt.dll OR *\\\\\\\\WmiApRpl.dll OR *\\\\\\\\wmiprov.dll OR *\\\\\\\\wmiutils.dll OR *\\\\\\\\wbemcomn.dll OR *\\\\\\\\wbemprox.dll OR *\\\\\\\\WMINet_Utils.dll OR *\\\\\\\\wbemsvc.dll OR *\\\\\\\\fastprox.dll)) AND (NOT (Image.keyword:(*\\\\\\\\WmiPrvSe.exe OR *\\\\\\\\WmiAPsrv.exe OR *\\\\\\\\svchost.exe))))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'WMI Modules Loaded\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\nComputerName = {{_source.ComputerName}}\\n        User = {{_source.User}}\\n       Image = {{_source.Image}}\\n ImageLoaded = {{_source.ImageLoaded}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((EventID:"7" AND ImageLoaded.keyword:(*\\\\wmiclnt.dll *\\\\WmiApRpl.dll *\\\\wmiprov.dll *\\\\wmiutils.dll *\\\\wbemcomn.dll *\\\\wbemprox.dll *\\\\WMINet_Utils.dll *\\\\wbemsvc.dll *\\\\fastprox.dll)) AND (NOT (Image.keyword:(*\\\\WmiPrvSe.exe *\\\\WmiAPsrv.exe *\\\\svchost.exe))))
```


### splunk
    
```
((EventID="7" (ImageLoaded="*\\\\wmiclnt.dll" OR ImageLoaded="*\\\\WmiApRpl.dll" OR ImageLoaded="*\\\\wmiprov.dll" OR ImageLoaded="*\\\\wmiutils.dll" OR ImageLoaded="*\\\\wbemcomn.dll" OR ImageLoaded="*\\\\wbemprox.dll" OR ImageLoaded="*\\\\WMINet_Utils.dll" OR ImageLoaded="*\\\\wbemsvc.dll" OR ImageLoaded="*\\\\fastprox.dll")) NOT ((Image="*\\\\WmiPrvSe.exe" OR Image="*\\\\WmiAPsrv.exe" OR Image="*\\\\svchost.exe"))) | table ComputerName,User,Image,ImageLoaded
```


### logpoint
    
```
((event_id="7" ImageLoaded IN ["*\\\\wmiclnt.dll", "*\\\\WmiApRpl.dll", "*\\\\wmiprov.dll", "*\\\\wmiutils.dll", "*\\\\wbemcomn.dll", "*\\\\wbemprox.dll", "*\\\\WMINet_Utils.dll", "*\\\\wbemsvc.dll", "*\\\\fastprox.dll"])  -(Image IN ["*\\\\WmiPrvSe.exe", "*\\\\WmiAPsrv.exe", "*\\\\svchost.exe"]))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*7)(?=.*(?:.*.*\\wmiclnt\\.dll|.*.*\\WmiApRpl\\.dll|.*.*\\wmiprov\\.dll|.*.*\\wmiutils\\.dll|.*.*\\wbemcomn\\.dll|.*.*\\wbemprox\\.dll|.*.*\\WMINet_Utils\\.dll|.*.*\\wbemsvc\\.dll|.*.*\\fastprox\\.dll))))(?=.*(?!.*(?:.*(?=.*(?:.*.*\\WmiPrvSe\\.exe|.*.*\\WmiAPsrv\\.exe|.*.*\\svchost\\.exe))))))'
```



