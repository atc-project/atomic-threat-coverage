| Title                | Possible Application Whitelisting Bypass via WinDbg/CDB as a shellcode runner                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Launch 64-bit shellcode from the x64_calc.wds file using cdb.exe.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1218: Signed Binary Proxy Execution](https://attack.mitre.org/techniques/T1218)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Trigger              | <ul><li>[T1218: Signed Binary Proxy Execution](../Triggers/T1218.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Legitimate use of debugging tools</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Cdb.yml](https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Cdb.yml)</li><li>[http://www.exploit-monday.com/2016/08/windbg-cdb-shellcode-runner.html](http://www.exploit-monday.com/2016/08/windbg-cdb-shellcode-runner.html)</li></ul>  |
| Author               | Beyu Denis, oscd.community |


## Detection Rules

### Sigma rule

```
title: Possible Application Whitelisting Bypass via WinDbg/CDB as a shellcode runner
id: b5c7395f-e501-4a08-94d4-57fe7a9da9d2
status: experimental
description: Launch 64-bit shellcode from the x64_calc.wds file using cdb.exe.
references:
    - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Cdb.yml
    - http://www.exploit-monday.com/2016/08/windbg-cdb-shellcode-runner.html
author: Beyu Denis, oscd.community
date: 2019/10/26
modified: 2019/11/04
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1218
level: medium
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\cdb.exe'
        CommandLine|contains: '-cf'
    condition: selection
falsepositives:
    - Legitimate use of debugging tools

```





### es-qs
    
```
(Image.keyword:*\\\\cdb.exe AND CommandLine.keyword:*\\-cf*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Possible-Application-Whitelisting-Bypass-via-WinDbg/CDB-as-a-shellcode-runner <<EOF\n{\n  "metadata": {\n    "title": "Possible Application Whitelisting Bypass via WinDbg/CDB as a shellcode runner",\n    "description": "Launch 64-bit shellcode from the x64_calc.wds file using cdb.exe.",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.execution",\n      "attack.t1218"\n    ],\n    "query": "(Image.keyword:*\\\\\\\\cdb.exe AND CommandLine.keyword:*\\\\-cf*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(Image.keyword:*\\\\\\\\cdb.exe AND CommandLine.keyword:*\\\\-cf*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Possible Application Whitelisting Bypass via WinDbg/CDB as a shellcode runner\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(Image.keyword:*\\\\cdb.exe AND CommandLine.keyword:*\\-cf*)
```


### splunk
    
```
(Image="*\\\\cdb.exe" CommandLine="*-cf*")
```


### logpoint
    
```
(event_id="1" Image="*\\\\cdb.exe" CommandLine="*-cf*")
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\\cdb\\.exe)(?=.*.*-cf.*))'
```



