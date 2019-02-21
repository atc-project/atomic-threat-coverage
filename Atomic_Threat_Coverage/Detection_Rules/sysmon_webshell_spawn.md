| Title                | Shells Spawned by Web Servers                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Web servers that spawn shell processes could be the result of a successfully placed web shell or an other attack                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1100: Web Shell](https://attack.mitre.org/techniques/T1100)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1100: Web Shell](../Triggers/T1100.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>Particular web applications may spawn a shell process legitimately</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul></ul>                                                          |
| Author               | Thomas Patzke                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Shells Spawned by Web Servers
status: experimental
description: Web servers that spawn shell processes could be the result of a successfully placed web shell or an other attack
author: Thomas Patzke
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1
        ParentImage:
            - '*\w3wp.exe'
            - '*\httpd.exe'
            - '*\nginx.exe'
            - '*\php-cgi.exe'
        Image:
            - '*\cmd.exe'
            - '*\sh.exe'
            - '*\bash.exe'
            - '*\powershell.exe'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
tags:
    - attack.privilege_escalation
    - attack.persistence
    - attack.t1100
falsepositives:
    - Particular web applications may spawn a shell process legitimately
level: high

```





### Kibana query

```
(EventID:"1" AND ParentImage.keyword:(*\\\\w3wp.exe *\\\\httpd.exe *\\\\nginx.exe *\\\\php\\-cgi.exe) AND Image.keyword:(*\\\\cmd.exe *\\\\sh.exe *\\\\bash.exe *\\\\powershell.exe))
```





### X-Pack Watcher

```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Shells-Spawned-by-Web-Servers <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"1\\" AND ParentImage.keyword:(*\\\\\\\\w3wp.exe *\\\\\\\\httpd.exe *\\\\\\\\nginx.exe *\\\\\\\\php\\\\-cgi.exe) AND Image.keyword:(*\\\\\\\\cmd.exe *\\\\\\\\sh.exe *\\\\\\\\bash.exe *\\\\\\\\powershell.exe))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Shells Spawned by Web Servers\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```





### Graylog

```
(EventID:"1" AND ParentImage:("*\\\\w3wp.exe" "*\\\\httpd.exe" "*\\\\nginx.exe" "*\\\\php\\-cgi.exe") AND Image:("*\\\\cmd.exe" "*\\\\sh.exe" "*\\\\bash.exe" "*\\\\powershell.exe"))
```





### Splunk

```
(EventID="1" (ParentImage="*\\\\w3wp.exe" OR ParentImage="*\\\\httpd.exe" OR ParentImage="*\\\\nginx.exe" OR ParentImage="*\\\\php-cgi.exe") (Image="*\\\\cmd.exe" OR Image="*\\\\sh.exe" OR Image="*\\\\bash.exe" OR Image="*\\\\powershell.exe")) | table CommandLine,ParentCommandLine
```





### Logpoint

```
(EventID="1" ParentImage IN ["*\\\\w3wp.exe", "*\\\\httpd.exe", "*\\\\nginx.exe", "*\\\\php-cgi.exe"] Image IN ["*\\\\cmd.exe", "*\\\\sh.exe", "*\\\\bash.exe", "*\\\\powershell.exe"])
```





### Grep

```
grep -P '^(?:.*(?=.*1)(?=.*(?:.*.*\\w3wp\\.exe|.*.*\\httpd\\.exe|.*.*\\nginx\\.exe|.*.*\\php-cgi\\.exe))(?=.*(?:.*.*\\cmd\\.exe|.*.*\\sh\\.exe|.*.*\\bash\\.exe|.*.*\\powershell\\.exe)))'
```





### Fieldlist

```
EventID\nImage\nParentImage
```

