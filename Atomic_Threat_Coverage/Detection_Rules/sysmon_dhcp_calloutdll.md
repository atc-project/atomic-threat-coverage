| Title                | DHCP Callout DLL installation                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects the installation of a Callout DLL via CalloutDlls and CalloutEnabled parameter in Registry, which can be used to execute code in context of the DHCP server (restart required)                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul></ul>  |
| ATT&amp;CK Technique | <ul></ul>                             |
| Data Needed          | <ul><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li></ul>                                                         |
| Trigger              |  There is no Trigger for this technique yet.  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>unknown</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://blog.3or.de/mimilib-dhcp-server-callout-dll-injection.html](https://blog.3or.de/mimilib-dhcp-server-callout-dll-injection.html)</li><li>[https://technet.microsoft.com/en-us/library/cc726884(v=ws.10).aspx](https://technet.microsoft.com/en-us/library/cc726884(v=ws.10).aspx)</li><li>[https://msdn.microsoft.com/de-de/library/windows/desktop/aa363389(v=vs.85).aspx](https://msdn.microsoft.com/de-de/library/windows/desktop/aa363389(v=vs.85).aspx)</li></ul>                                                          |
| Author               | Dimitrios Slamaris                                                                                                                                                |


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





### Kibana query

```
(EventID:"13" AND TargetObject.keyword:(*\\\\Services\\\\DHCPServer\\\\Parameters\\\\CalloutDlls *\\\\Services\\\\DHCPServer\\\\Parameters\\\\CalloutEnabled))
```





### X-Pack Watcher

```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/DHCP-Callout-DLL-installation <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"13\\" AND TargetObject.keyword:(*\\\\\\\\Services\\\\\\\\DHCPServer\\\\\\\\Parameters\\\\\\\\CalloutDlls *\\\\\\\\Services\\\\\\\\DHCPServer\\\\\\\\Parameters\\\\\\\\CalloutEnabled))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'DHCP Callout DLL installation\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```





### Graylog

```
(EventID:"13" AND TargetObject:("*\\\\Services\\\\DHCPServer\\\\Parameters\\\\CalloutDlls" "*\\\\Services\\\\DHCPServer\\\\Parameters\\\\CalloutEnabled"))
```





### Splunk

```
(EventID="13" (TargetObject="*\\\\Services\\\\DHCPServer\\\\Parameters\\\\CalloutDlls" OR TargetObject="*\\\\Services\\\\DHCPServer\\\\Parameters\\\\CalloutEnabled"))
```





### Logpoint

```
(EventID="13" TargetObject IN ["*\\\\Services\\\\DHCPServer\\\\Parameters\\\\CalloutDlls", "*\\\\Services\\\\DHCPServer\\\\Parameters\\\\CalloutEnabled"])
```





### Grep

```
grep -P '^(?:.*(?=.*13)(?=.*(?:.*.*\\Services\\DHCPServer\\Parameters\\CalloutDlls|.*.*\\Services\\DHCPServer\\Parameters\\CalloutEnabled)))'
```





### Fieldlist

```
EventID\nTargetObject
```

