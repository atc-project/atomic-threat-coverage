| Title                | Relevant Anti-Virus Event                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | This detection method points out highly relevant Antivirus events                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul></ul>  |
| ATT&amp;CK Technique | <ul></ul>                             |
| Data Needed          | <ul></ul>                                                         |
| Trigger              |  There is no Trigger for this technique yet.  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>Some software piracy tools (key generators, cracks) are classified as hack tools</li></ul>                                                                  |
| Development Status   |                                                                                                                                                 |
| References           | <ul></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Relevant Anti-Virus Event
description: This detection method points out highly relevant Antivirus events
author: Florian Roth
logsource:
    product: windows
    service: application
detection:
    keywords:
        - HTool
        - Hacktool
        - ASP/Backdoor
        - JSP/Backdoor
        - PHP/Backdoor
        - Backdoor.ASP
        - Backdoor.JSP
        - Backdoor.PHP
        - Webshell
        - Portscan
        - Mimikatz
        - WinCred
        - PlugX
        - Korplug
        - Pwdump
        - Chopper
        - WmiExec
        - Xscan
        - Clearlog
        - ASPXSpy
    filters:
        - Keygen
        - Crack
    condition: keywords and not 1 of filters
falsepositives:
    - Some software piracy tools (key generators, cracks) are classified as hack tools
level: high

```




### esqs
    
```
((HTool OR Hacktool OR ASP\\/Backdoor OR JSP\\/Backdoor OR PHP\\/Backdoor OR Backdoor.ASP OR Backdoor.JSP OR Backdoor.PHP OR Webshell OR Portscan OR Mimikatz OR WinCred OR PlugX OR Korplug OR Pwdump OR Chopper OR WmiExec OR Xscan OR Clearlog OR ASPXSpy) AND NOT (Keygen OR Crack))
```


### xpackwatcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Relevant-Anti-Virus-Event <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "((HTool OR Hacktool OR ASP\\\\/Backdoor OR JSP\\\\/Backdoor OR PHP\\\\/Backdoor OR Backdoor.ASP OR Backdoor.JSP OR Backdoor.PHP OR Webshell OR Portscan OR Mimikatz OR WinCred OR PlugX OR Korplug OR Pwdump OR Chopper OR WmiExec OR Xscan OR Clearlog OR ASPXSpy) AND NOT (Keygen OR Crack))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Relevant Anti-Virus Event\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(("HTool" OR "Hacktool" OR "ASP\\/Backdoor" OR "JSP\\/Backdoor" OR "PHP\\/Backdoor" OR "Backdoor.ASP" OR "Backdoor.JSP" OR "Backdoor.PHP" OR "Webshell" OR "Portscan" OR "Mimikatz" OR "WinCred" OR "PlugX" OR "Korplug" OR "Pwdump" OR "Chopper" OR "WmiExec" OR "Xscan" OR "Clearlog" OR "ASPXSpy") AND NOT ("Keygen" OR "Crack"))
```


### splunk
    
```
(("HTool" OR "Hacktool" OR "ASP/Backdoor" OR "JSP/Backdoor" OR "PHP/Backdoor" OR "Backdoor.ASP" OR "Backdoor.JSP" OR "Backdoor.PHP" OR "Webshell" OR "Portscan" OR "Mimikatz" OR "WinCred" OR "PlugX" OR "Korplug" OR "Pwdump" OR "Chopper" OR "WmiExec" OR "Xscan" OR "Clearlog" OR "ASPXSpy") NOT ("Keygen" OR "Crack"))
```


### logpoint
    
```
(("HTool" OR "Hacktool" OR "ASP/Backdoor" OR "JSP/Backdoor" OR "PHP/Backdoor" OR "Backdoor.ASP" OR "Backdoor.JSP" OR "Backdoor.PHP" OR "Webshell" OR "Portscan" OR "Mimikatz" OR "WinCred" OR "PlugX" OR "Korplug" OR "Pwdump" OR "Chopper" OR "WmiExec" OR "Xscan" OR "Clearlog" OR "ASPXSpy")  -("Keygen" OR "Crack"))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?:.*HTool|.*Hacktool|.*ASP/Backdoor|.*JSP/Backdoor|.*PHP/Backdoor|.*Backdoor\\.ASP|.*Backdoor\\.JSP|.*Backdoor\\.PHP|.*Webshell|.*Portscan|.*Mimikatz|.*WinCred|.*PlugX|.*Korplug|.*Pwdump|.*Chopper|.*WmiExec|.*Xscan|.*Clearlog|.*ASPXSpy)))(?=.*(?!.*(?:.*(?:.*Keygen|.*Crack)))))'
```


