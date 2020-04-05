| Title                    | Relevant Anti-Virus Event       |
|:-------------------------|:------------------|
| **Description**          | This detection method points out highly relevant Antivirus events |
| **ATT&amp;CK Tactic**    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| **ATT&amp;CK Technique** |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Some software piracy tools (key generators, cracks) are classified as hack tools</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Relevant Anti-Virus Event
id: 78bc5783-81d9-4d73-ac97-59f6db4f72a8
description: This detection method points out highly relevant Antivirus events
author: Florian Roth
date: 2017/02/19
logsource:
    product: windows
    service: application
detection:
    keywords:
        Message:
            - "*HTool*"
            - "*Hacktool*"
            - "*ASP/Backdoor*"
            - "*JSP/Backdoor*"
            - "*PHP/Backdoor*"
            - "*Backdoor.ASP*"
            - "*Backdoor.JSP*"
            - "*Backdoor.PHP*"
            - "*Webshell*"
            - "*Portscan*"
            - "*Mimikatz*"
            - "*WinCred*"
            - "*PlugX*"
            - "*Korplug*"
            - "*Pwdump*"
            - "*Chopper*"
            - "*WmiExec*"
            - "*Xscan*"
            - "*Clearlog*"
            - "*ASPXSpy*"
    filters:
        Message:
            - "*Keygen*"
            - "*Crack*"
    condition: keywords and not 1 of filters
falsepositives:
    - Some software piracy tools (key generators, cracks) are classified as hack tools
level: high

```





### es-qs
    
```
(Message.keyword:(*HTool* OR *Hacktool* OR *ASP\\/Backdoor* OR *JSP\\/Backdoor* OR *PHP\\/Backdoor* OR *Backdoor.ASP* OR *Backdoor.JSP* OR *Backdoor.PHP* OR *Webshell* OR *Portscan* OR *Mimikatz* OR *WinCred* OR *PlugX* OR *Korplug* OR *Pwdump* OR *Chopper* OR *WmiExec* OR *Xscan* OR *Clearlog* OR *ASPXSpy*) AND (NOT (Message.keyword:(*Keygen* OR *Crack*))))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/78bc5783-81d9-4d73-ac97-59f6db4f72a8 <<EOF\n{\n  "metadata": {\n    "title": "Relevant Anti-Virus Event",\n    "description": "This detection method points out highly relevant Antivirus events",\n    "tags": "",\n    "query": "(Message.keyword:(*HTool* OR *Hacktool* OR *ASP\\\\/Backdoor* OR *JSP\\\\/Backdoor* OR *PHP\\\\/Backdoor* OR *Backdoor.ASP* OR *Backdoor.JSP* OR *Backdoor.PHP* OR *Webshell* OR *Portscan* OR *Mimikatz* OR *WinCred* OR *PlugX* OR *Korplug* OR *Pwdump* OR *Chopper* OR *WmiExec* OR *Xscan* OR *Clearlog* OR *ASPXSpy*) AND (NOT (Message.keyword:(*Keygen* OR *Crack*))))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(Message.keyword:(*HTool* OR *Hacktool* OR *ASP\\\\/Backdoor* OR *JSP\\\\/Backdoor* OR *PHP\\\\/Backdoor* OR *Backdoor.ASP* OR *Backdoor.JSP* OR *Backdoor.PHP* OR *Webshell* OR *Portscan* OR *Mimikatz* OR *WinCred* OR *PlugX* OR *Korplug* OR *Pwdump* OR *Chopper* OR *WmiExec* OR *Xscan* OR *Clearlog* OR *ASPXSpy*) AND (NOT (Message.keyword:(*Keygen* OR *Crack*))))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Relevant Anti-Virus Event\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(Message.keyword:(*HTool* *Hacktool* *ASP\\/Backdoor* *JSP\\/Backdoor* *PHP\\/Backdoor* *Backdoor.ASP* *Backdoor.JSP* *Backdoor.PHP* *Webshell* *Portscan* *Mimikatz* *WinCred* *PlugX* *Korplug* *Pwdump* *Chopper* *WmiExec* *Xscan* *Clearlog* *ASPXSpy*) AND (NOT (Message.keyword:(*Keygen* *Crack*))))
```


### splunk
    
```
((Message="*HTool*" OR Message="*Hacktool*" OR Message="*ASP/Backdoor*" OR Message="*JSP/Backdoor*" OR Message="*PHP/Backdoor*" OR Message="*Backdoor.ASP*" OR Message="*Backdoor.JSP*" OR Message="*Backdoor.PHP*" OR Message="*Webshell*" OR Message="*Portscan*" OR Message="*Mimikatz*" OR Message="*WinCred*" OR Message="*PlugX*" OR Message="*Korplug*" OR Message="*Pwdump*" OR Message="*Chopper*" OR Message="*WmiExec*" OR Message="*Xscan*" OR Message="*Clearlog*" OR Message="*ASPXSpy*") NOT ((Message="*Keygen*" OR Message="*Crack*")))
```


### logpoint
    
```
(Message IN ["*HTool*", "*Hacktool*", "*ASP/Backdoor*", "*JSP/Backdoor*", "*PHP/Backdoor*", "*Backdoor.ASP*", "*Backdoor.JSP*", "*Backdoor.PHP*", "*Webshell*", "*Portscan*", "*Mimikatz*", "*WinCred*", "*PlugX*", "*Korplug*", "*Pwdump*", "*Chopper*", "*WmiExec*", "*Xscan*", "*Clearlog*", "*ASPXSpy*"]  -(Message IN ["*Keygen*", "*Crack*"]))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*HTool.*|.*.*Hacktool.*|.*.*ASP/Backdoor.*|.*.*JSP/Backdoor.*|.*.*PHP/Backdoor.*|.*.*Backdoor\\.ASP.*|.*.*Backdoor\\.JSP.*|.*.*Backdoor\\.PHP.*|.*.*Webshell.*|.*.*Portscan.*|.*.*Mimikatz.*|.*.*WinCred.*|.*.*PlugX.*|.*.*Korplug.*|.*.*Pwdump.*|.*.*Chopper.*|.*.*WmiExec.*|.*.*Xscan.*|.*.*Clearlog.*|.*.*ASPXSpy.*))(?=.*(?!.*(?:.*(?=.*(?:.*.*Keygen.*|.*.*Crack.*))))))'
```



