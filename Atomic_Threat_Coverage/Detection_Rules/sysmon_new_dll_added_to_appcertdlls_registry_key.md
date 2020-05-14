| Title                    | New DLL Added to AppCertDlls Registry Key       |
|:-------------------------|:------------------|
| **Description**          | Dynamic-link libraries (DLLs) that are specified in the AppCertDLLs value in the Registry key can be abused to obtain persistence and privilege escalation by causing a malicious DLL to be loaded and run in the context of separate processes on the computer. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1182: AppCert DLLs](https://attack.mitre.org/techniques/T1182)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0016_12_windows_sysmon_RegistryEvent](../Data_Needed/DN_0016_12_windows_sysmon_RegistryEvent.md)</li><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li><li>[DN_0018_14_windows_sysmon_RegistryEvent](../Data_Needed/DN_0018_14_windows_sysmon_RegistryEvent.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Unkown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[http://www.hexacorn.com/blog/2013/01/19/beyond-good-ol-run-key-part-3/](http://www.hexacorn.com/blog/2013/01/19/beyond-good-ol-run-key-part-3/)</li><li>[https://eqllib.readthedocs.io/en/latest/analytics/14f90406-10a0-4d36-a672-31cabe149f2f.html](https://eqllib.readthedocs.io/en/latest/analytics/14f90406-10a0-4d36-a672-31cabe149f2f.html)</li></ul>  |
| **Author**               | Ilyas Ochkov, oscd.community |


## Detection Rules

### Sigma rule

```
title: New DLL Added to AppCertDlls Registry Key
id: 6aa1d992-5925-4e9f-a49b-845e51d1de01
status: experimental
description: Dynamic-link libraries (DLLs) that are specified in the AppCertDLLs value in the Registry key can be abused to obtain persistence and privilege escalation
    by causing a malicious DLL to be loaded and run in the context of separate processes on the computer.
references:
    - http://www.hexacorn.com/blog/2013/01/19/beyond-good-ol-run-key-part-3/
    - https://eqllib.readthedocs.io/en/latest/analytics/14f90406-10a0-4d36-a672-31cabe149f2f.html
tags:
    - attack.persistence
    - attack.t1182
author: Ilyas Ochkov, oscd.community
date: 2019/10/25
modified: 2019/11/13
logsource:
    product: windows
    service: sysmon
detection:
    selection:
      - EventID: 
            - 12  # key create
            - 13  # value set
        # Sysmon gives us HKLM\SYSTEM\CurrentControlSet\.. if ControlSetXX is the selected one
        TargetObject: 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls'
      - EventID: 14  # key rename
        NewName: 'HKLM\SYSTEM\CurentControlSet\Control\Session Manager\AppCertDlls'
    condition: selection
fields:
    - EventID
    - Image
    - TargetObject
    - NewName
falsepositives:
    - Unkown
level: medium

```





### es-qs
    
```
((EventID:("12" OR "13") AND TargetObject:"HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\Session\\ Manager\\\\AppCertDlls") OR (EventID:"14" AND NewName:"HKLM\\\\SYSTEM\\\\CurentControlSet\\\\Control\\\\Session\\ Manager\\\\AppCertDlls"))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/6aa1d992-5925-4e9f-a49b-845e51d1de01 <<EOF\n{\n  "metadata": {\n    "title": "New DLL Added to AppCertDlls Registry Key",\n    "description": "Dynamic-link libraries (DLLs) that are specified in the AppCertDLLs value in the Registry key can be abused to obtain persistence and privilege escalation by causing a malicious DLL to be loaded and run in the context of separate processes on the computer.",\n    "tags": [\n      "attack.persistence",\n      "attack.t1182"\n    ],\n    "query": "((EventID:(\\"12\\" OR \\"13\\") AND TargetObject:\\"HKLM\\\\\\\\SYSTEM\\\\\\\\CurrentControlSet\\\\\\\\Control\\\\\\\\Session\\\\ Manager\\\\\\\\AppCertDlls\\") OR (EventID:\\"14\\" AND NewName:\\"HKLM\\\\\\\\SYSTEM\\\\\\\\CurentControlSet\\\\\\\\Control\\\\\\\\Session\\\\ Manager\\\\\\\\AppCertDlls\\"))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((EventID:(\\"12\\" OR \\"13\\") AND TargetObject:\\"HKLM\\\\\\\\SYSTEM\\\\\\\\CurrentControlSet\\\\\\\\Control\\\\\\\\Session\\\\ Manager\\\\\\\\AppCertDlls\\") OR (EventID:\\"14\\" AND NewName:\\"HKLM\\\\\\\\SYSTEM\\\\\\\\CurentControlSet\\\\\\\\Control\\\\\\\\Session\\\\ Manager\\\\\\\\AppCertDlls\\"))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'New DLL Added to AppCertDlls Registry Key\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n     EventID = {{_source.EventID}}\\n       Image = {{_source.Image}}\\nTargetObject = {{_source.TargetObject}}\\n     NewName = {{_source.NewName}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((EventID:("12" "13") AND TargetObject:"HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\Session Manager\\\\AppCertDlls") OR (EventID:"14" AND NewName:"HKLM\\\\SYSTEM\\\\CurentControlSet\\\\Control\\\\Session Manager\\\\AppCertDlls"))
```


### splunk
    
```
(((EventID="12" OR EventID="13") TargetObject="HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\Session Manager\\\\AppCertDlls") OR (EventID="14" NewName="HKLM\\\\SYSTEM\\\\CurentControlSet\\\\Control\\\\Session Manager\\\\AppCertDlls")) | table EventID,Image,TargetObject,NewName
```


### logpoint
    
```
((event_id IN ["12", "13"] TargetObject="HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\Session Manager\\\\AppCertDlls") OR (event_id="14" NewName="HKLM\\\\SYSTEM\\\\CurentControlSet\\\\Control\\\\Session Manager\\\\AppCertDlls"))
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*(?=.*(?:.*12|.*13))(?=.*HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls))|.*(?:.*(?=.*14)(?=.*HKLM\\SYSTEM\\CurentControlSet\\Control\\Session Manager\\AppCertDlls))))'
```



