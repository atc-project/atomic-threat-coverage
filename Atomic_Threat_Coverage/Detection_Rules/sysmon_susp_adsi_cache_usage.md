| Title                    | Suspicious ADSI-Cache Usage By Unknown Tool       |
|:-------------------------|:------------------|
| **Description**          | detects the usage of ADSI (LDAP) operations by tools. This may also detect tools like LDAPFragger. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1041: Exfiltration Over Command and Control Channel](https://attack.mitre.org/techniques/T1041)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0015_11_windows_sysmon_FileCreate](../Data_Needed/DN_0015_11_windows_sysmon_FileCreate.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1041: Exfiltration Over Command and Control Channel](../Triggers/T1041.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Other legimate tools, which do ADSI (LDAP) operations, e.g. any remoting activity by MMC, Powershell, Windows etc.</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://medium.com/@ivecodoe/detecting-ldapfragger-a-newly-released-cobalt-strike-beacon-using-ldap-for-c2-communication-c274a7f00961](https://medium.com/@ivecodoe/detecting-ldapfragger-a-newly-released-cobalt-strike-beacon-using-ldap-for-c2-communication-c274a7f00961)</li><li>[https://blog.fox-it.com/2020/03/19/ldapfragger-command-and-control-over-ldap-attributes/](https://blog.fox-it.com/2020/03/19/ldapfragger-command-and-control-over-ldap-attributes/)</li><li>[https://github.com/fox-it/LDAPFragger](https://github.com/fox-it/LDAPFragger)</li></ul>  |
| **Author**               | xknow @xknow_infosec |


## Detection Rules

### Sigma rule

```
title: Suspicious ADSI-Cache Usage By Unknown Tool
id: 75bf09fa-1dd7-4d18-9af9-dd9e492562eb
description: detects the usage of ADSI (LDAP) operations by tools. This may also detect tools like LDAPFragger.
status: experimental
date: 2019/03/24
author: xknow @xknow_infosec
references:
    - https://medium.com/@ivecodoe/detecting-ldapfragger-a-newly-released-cobalt-strike-beacon-using-ldap-for-c2-communication-c274a7f00961
    - https://blog.fox-it.com/2020/03/19/ldapfragger-command-and-control-over-ldap-attributes/
    - https://github.com/fox-it/LDAPFragger
tags:
    - attack.t1041
    - attack.persistence
logsource:
    product: windows
    service: sysmon
detection:
    selection_1:
        EventID: 11
        TargetFilename: '*\Local\Microsoft\Windows\SchCache\*.sch'
    selection_2:
        Image|contains:
            - 'C:\windows\system32\svchost.exe'
            - 'C:\windows\system32\dllhost.exe'
            - 'C:\windows\system32\mmc.exe'
            - 'C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe'
    condition: selection_1 and not selection_2
falsepositives:
    - Other legimate tools, which do ADSI (LDAP) operations, e.g. any remoting activity by MMC, Powershell, Windows etc.
level: high

```





### es-qs
    
```
((EventID:"11" AND TargetFilename.keyword:*\\\\Local\\\\Microsoft\\\\Windows\\\\SchCache\\*.sch) AND (NOT (Image.keyword:(*C\\:\\\\windows\\\\system32\\\\svchost.exe* OR *C\\:\\\\windows\\\\system32\\\\dllhost.exe* OR *C\\:\\\\windows\\\\system32\\\\mmc.exe* OR *C\\:\\\\windows\\\\system32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe*))))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/75bf09fa-1dd7-4d18-9af9-dd9e492562eb <<EOF\n{\n  "metadata": {\n    "title": "Suspicious ADSI-Cache Usage By Unknown Tool",\n    "description": "detects the usage of ADSI (LDAP) operations by tools. This may also detect tools like LDAPFragger.",\n    "tags": [\n      "attack.t1041",\n      "attack.persistence"\n    ],\n    "query": "((EventID:\\"11\\" AND TargetFilename.keyword:*\\\\\\\\Local\\\\\\\\Microsoft\\\\\\\\Windows\\\\\\\\SchCache\\\\*.sch) AND (NOT (Image.keyword:(*C\\\\:\\\\\\\\windows\\\\\\\\system32\\\\\\\\svchost.exe* OR *C\\\\:\\\\\\\\windows\\\\\\\\system32\\\\\\\\dllhost.exe* OR *C\\\\:\\\\\\\\windows\\\\\\\\system32\\\\\\\\mmc.exe* OR *C\\\\:\\\\\\\\windows\\\\\\\\system32\\\\\\\\WindowsPowerShell\\\\\\\\v1.0\\\\\\\\powershell.exe*))))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((EventID:\\"11\\" AND TargetFilename.keyword:*\\\\\\\\Local\\\\\\\\Microsoft\\\\\\\\Windows\\\\\\\\SchCache\\\\*.sch) AND (NOT (Image.keyword:(*C\\\\:\\\\\\\\windows\\\\\\\\system32\\\\\\\\svchost.exe* OR *C\\\\:\\\\\\\\windows\\\\\\\\system32\\\\\\\\dllhost.exe* OR *C\\\\:\\\\\\\\windows\\\\\\\\system32\\\\\\\\mmc.exe* OR *C\\\\:\\\\\\\\windows\\\\\\\\system32\\\\\\\\WindowsPowerShell\\\\\\\\v1.0\\\\\\\\powershell.exe*))))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Suspicious ADSI-Cache Usage By Unknown Tool\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((EventID:"11" AND TargetFilename.keyword:*\\\\Local\\\\Microsoft\\\\Windows\\\\SchCache\\*.sch) AND (NOT (Image.keyword:(*C\\:\\\\windows\\\\system32\\\\svchost.exe* *C\\:\\\\windows\\\\system32\\\\dllhost.exe* *C\\:\\\\windows\\\\system32\\\\mmc.exe* *C\\:\\\\windows\\\\system32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe*))))
```


### splunk
    
```
((EventID="11" TargetFilename="*\\\\Local\\\\Microsoft\\\\Windows\\\\SchCache\\*.sch") NOT ((Image="*C:\\\\windows\\\\system32\\\\svchost.exe*" OR Image="*C:\\\\windows\\\\system32\\\\dllhost.exe*" OR Image="*C:\\\\windows\\\\system32\\\\mmc.exe*" OR Image="*C:\\\\windows\\\\system32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe*")))
```


### logpoint
    
```
((event_id="11" TargetFilename="*\\\\Local\\\\Microsoft\\\\Windows\\\\SchCache\\*.sch")  -(Image IN ["*C:\\\\windows\\\\system32\\\\svchost.exe*", "*C:\\\\windows\\\\system32\\\\dllhost.exe*", "*C:\\\\windows\\\\system32\\\\mmc.exe*", "*C:\\\\windows\\\\system32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe*"]))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*11)(?=.*.*\\Local\\Microsoft\\Windows\\SchCache\\.*\\.sch)))(?=.*(?!.*(?:.*(?=.*(?:.*.*C:\\windows\\system32\\svchost\\.exe.*|.*.*C:\\windows\\system32\\dllhost\\.exe.*|.*.*C:\\windows\\system32\\mmc\\.exe.*|.*.*C:\\windows\\system32\\WindowsPowerShell\\v1\\.0\\powershell\\.exe.*))))))'
```



