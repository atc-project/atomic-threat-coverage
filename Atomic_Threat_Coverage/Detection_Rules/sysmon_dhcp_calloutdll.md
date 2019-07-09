| Title                | DHCP Callout DLL installation                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects the installation of a Callout DLL via CalloutDlls and CalloutEnabled parameter in Registry, which can be used to execute code in context of the DHCP server (restart required)                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1073: DLL Side-Loading](https://attack.mitre.org/techniques/T1073)</li><li>[T1112: Modify Registry](https://attack.mitre.org/techniques/T1112)</li></ul>  |
| Data Needed          | <ul><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1073: DLL Side-Loading](../Triggers/T1073.md)</li><li>[T1112: Modify Registry](../Triggers/T1112.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://blog.3or.de/mimilib-dhcp-server-callout-dll-injection.html](https://blog.3or.de/mimilib-dhcp-server-callout-dll-injection.html)</li><li>[https://technet.microsoft.com/en-us/library/cc726884(v=ws.10).aspx](https://technet.microsoft.com/en-us/library/cc726884(v=ws.10).aspx)</li><li>[https://msdn.microsoft.com/de-de/library/windows/desktop/aa363389(v=vs.85).aspx](https://msdn.microsoft.com/de-de/library/windows/desktop/aa363389(v=vs.85).aspx)</li></ul>  |
| Author               | Dimitrios Slamaris |


## Detection Rules

### Sigma rule

```
title: DHCP Callout DLL installation
status: experimental
description: Detects the installation of a Callout DLL via CalloutDlls and CalloutEnabled parameter in Registry, which can be used to execute code in context of the DHCP server (restart required)
references:
    - https://blog.3or.de/mimilib-dhcp-server-callout-dll-injection.html
    - https://technet.microsoft.com/en-us/library/cc726884(v=ws.10).aspx
    - https://msdn.microsoft.com/de-de/library/windows/desktop/aa363389(v=vs.85).aspx
date: 2017/05/15
author: Dimitrios Slamaris
tags:
    - attack.defense_evasion
    - attack.t1073
    - attack.t1112
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 13
        TargetObject: 
            - '*\Services\DHCPServer\Parameters\CalloutDlls'
            - '*\Services\DHCPServer\Parameters\CalloutEnabled'
    condition: selection
falsepositives:
    - unknown
level: high

```





### es-qs
    
```
(EventID:"13" AND TargetObject.keyword:(*\\\\Services\\\\DHCPServer\\\\Parameters\\\\CalloutDlls *\\\\Services\\\\DHCPServer\\\\Parameters\\\\CalloutEnabled))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/DHCP-Callout-DLL-installation <<EOF\n{\n  "metadata": {\n    "title": "DHCP Callout DLL installation",\n    "description": "Detects the installation of a Callout DLL via CalloutDlls and CalloutEnabled parameter in Registry, which can be used to execute code in context of the DHCP server (restart required)",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1073",\n      "attack.t1112"\n    ],\n    "query": "(EventID:\\"13\\" AND TargetObject.keyword:(*\\\\\\\\Services\\\\\\\\DHCPServer\\\\\\\\Parameters\\\\\\\\CalloutDlls *\\\\\\\\Services\\\\\\\\DHCPServer\\\\\\\\Parameters\\\\\\\\CalloutEnabled))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"13\\" AND TargetObject.keyword:(*\\\\\\\\Services\\\\\\\\DHCPServer\\\\\\\\Parameters\\\\\\\\CalloutDlls *\\\\\\\\Services\\\\\\\\DHCPServer\\\\\\\\Parameters\\\\\\\\CalloutEnabled))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'DHCP Callout DLL installation\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"13" AND TargetObject:("*\\\\Services\\\\DHCPServer\\\\Parameters\\\\CalloutDlls" "*\\\\Services\\\\DHCPServer\\\\Parameters\\\\CalloutEnabled"))
```


### splunk
    
```
(EventID="13" (TargetObject="*\\\\Services\\\\DHCPServer\\\\Parameters\\\\CalloutDlls" OR TargetObject="*\\\\Services\\\\DHCPServer\\\\Parameters\\\\CalloutEnabled"))
```


### logpoint
    
```
(EventID="13" TargetObject IN ["*\\\\Services\\\\DHCPServer\\\\Parameters\\\\CalloutDlls", "*\\\\Services\\\\DHCPServer\\\\Parameters\\\\CalloutEnabled"])
```


### grep
    
```
grep -P '^(?:.*(?=.*13)(?=.*(?:.*.*\\Services\\DHCPServer\\Parameters\\CalloutDlls|.*.*\\Services\\DHCPServer\\Parameters\\CalloutEnabled)))'
```



