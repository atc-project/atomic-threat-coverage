| Title                | Relevant Anti-Virus Event                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | This detection method points out highly relevant Antivirus events                                                                                                                                           |
| ATT&amp;CK Tactic    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| ATT&amp;CK Technique |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| Data Needed          |  There is no documented Data Needed for this Detection Rule yet  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              |  There is no documented Trigger for this Detection Rule yet  |
| Severity Level       | high |
| False Positives      | <ul><li>Some software piracy tools (key generators, cracks) are classified as hack tools</li></ul>  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Florian Roth |


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





### es-qs
    
```
((HTool OR Hacktool OR ASP\\/Backdoor OR JSP\\/Backdoor OR PHP\\/Backdoor OR Backdoor.ASP OR Backdoor.JSP OR Backdoor.PHP OR Webshell OR Portscan OR Mimikatz OR WinCred OR PlugX OR Korplug OR Pwdump OR Chopper OR WmiExec OR Xscan OR Clearlog OR ASPXSpy) AND (NOT (Keygen OR Crack)))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Relevant-Anti-Virus-Event <<EOF\n{\n  "metadata": {\n    "title": "Relevant Anti-Virus Event",\n    "description": "This detection method points out highly relevant Antivirus events",\n    "tags": "",\n    "query": "((HTool OR Hacktool OR ASP\\\\/Backdoor OR JSP\\\\/Backdoor OR PHP\\\\/Backdoor OR Backdoor.ASP OR Backdoor.JSP OR Backdoor.PHP OR Webshell OR Portscan OR Mimikatz OR WinCred OR PlugX OR Korplug OR Pwdump OR Chopper OR WmiExec OR Xscan OR Clearlog OR ASPXSpy) AND (NOT (Keygen OR Crack)))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((HTool OR Hacktool OR ASP\\\\/Backdoor OR JSP\\\\/Backdoor OR PHP\\\\/Backdoor OR Backdoor.ASP OR Backdoor.JSP OR Backdoor.PHP OR Webshell OR Portscan OR Mimikatz OR WinCred OR PlugX OR Korplug OR Pwdump OR Chopper OR WmiExec OR Xscan OR Clearlog OR ASPXSpy) AND (NOT (Keygen OR Crack)))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Relevant Anti-Virus Event\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
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



