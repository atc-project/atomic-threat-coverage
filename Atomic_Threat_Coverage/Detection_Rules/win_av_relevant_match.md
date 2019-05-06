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





### es-qs
    
```

```


### xpack-watcher
    
```

```


### graylog
    
```
(("HTool" OR "Hacktool" OR "ASP\\/Backdoor" OR "JSP\\/Backdoor" OR "PHP\\/Backdoor" OR "Backdoor.ASP" OR "Backdoor.JSP" OR "Backdoor.PHP" OR "Webshell" OR "Portscan" OR "Mimikatz" OR "WinCred" OR "PlugX" OR "Korplug" OR "Pwdump" OR "Chopper" OR "WmiExec" OR "Xscan" OR "Clearlog" OR "ASPXSpy") AND NOT ("Keygen" OR "Crack"))
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?:.*HTool|.*Hacktool|.*ASP/Backdoor|.*JSP/Backdoor|.*PHP/Backdoor|.*Backdoor\\.ASP|.*Backdoor\\.JSP|.*Backdoor\\.PHP|.*Webshell|.*Portscan|.*Mimikatz|.*WinCred|.*PlugX|.*Korplug|.*Pwdump|.*Chopper|.*WmiExec|.*Xscan|.*Clearlog|.*ASPXSpy)))(?=.*(?!.*(?:.*(?:.*Keygen|.*Crack)))))'
```



