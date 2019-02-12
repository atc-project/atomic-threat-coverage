| Title                | DNS ServerLevelPluginDll Install                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects the installation of a plugin DLL via ServerLevelPluginDll parameter in Registry, which can be used to execute code in context of the DNS server (restart required)                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul></ul>  |
| ATT&amp;CK Technique | <ul></ul>                             |
| Data Needed          | <ul><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              |  There is no Trigger for this technique yet.  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>unknown</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83](https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83)</li></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: DNS ServerLevelPluginDll Install
status: experimental
description: Detects the installation of a plugin DLL via ServerLevelPluginDll parameter in Registry, which can be used to execute code in context of the DNS server (restart required)
references:
    - https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83
date: 2017/05/08
author: Florian Roth
logsource:
    product: windows
    service: sysmon
detection:
    dnsadmin:
        EventID: 1
        CommandLine: 'dnscmd.exe /config /serverlevelplugindll *'
    dnsregmod:
        EventID: 13
        TargetObject: '*\services\DNS\Parameters\ServerLevelPluginDll'
    condition: 1 of them
fields:
    - EventID
    - CommandLine
    - ParentCommandLine
    - Image
    - User
    - TargetObject
falsepositives:
    - unknown
level: high



```





### Kibana query

```
((EventID:"1" AND CommandLine:"dnscmd.exe \\/config \\/serverlevelplugindll *") OR (EventID:"13" AND TargetObject:"*\\\\services\\\\DNS\\\\Parameters\\\\ServerLevelPluginDll"))
```





### X-Pack Watcher

```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/DNS-ServerLevelPluginDll-Install <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "((EventID:\\"1\\" AND CommandLine:\\"dnscmd.exe \\\\/config \\\\/serverlevelplugindll *\\") OR (EventID:\\"13\\" AND TargetObject:\\"*\\\\\\\\services\\\\\\\\DNS\\\\\\\\Parameters\\\\\\\\ServerLevelPluginDll\\"))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'DNS ServerLevelPluginDll Install\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n          EventID = {{_source.EventID}}\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}\\n            Image = {{_source.Image}}\\n             User = {{_source.User}}\\n     TargetObject = {{_source.TargetObject}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```





### Graylog

```
((EventID:"1" AND CommandLine:"dnscmd.exe \\/config \\/serverlevelplugindll *") OR (EventID:"13" AND TargetObject:"*\\\\services\\\\DNS\\\\Parameters\\\\ServerLevelPluginDll"))
```

