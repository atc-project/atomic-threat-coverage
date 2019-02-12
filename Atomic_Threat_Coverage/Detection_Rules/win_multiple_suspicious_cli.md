| Title                | Quick Execution of a Series of Suspicious Commands                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects multiple suspicious process in a limited timeframe                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul></ul>  |
| ATT&amp;CK Technique | <ul></ul>                             |
| Data Needed          | <ul><li>[DN_0001_4688_windows_process_creation](../Data_Needed/DN_0001_4688_windows_process_creation.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>                                                         |
| Trigger              |  There is no Trigger for this technique yet.  |
| Severity Level       | low                                                                                                                                                 |
| False Positives      | <ul><li>False positives depend on scripts and administrative tools used in the monitored environment</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://car.mitre.org/wiki/CAR-2013-04-002](https://car.mitre.org/wiki/CAR-2013-04-002)</li></ul>                                                          |
| Author               | juju4                                                                                                                                                |


## Detection Rules

### Sigma rule

```
action: global
title: Quick Execution of a Series of Suspicious Commands
description: Detects multiple suspicious process in a limited timeframe
status: experimental
references:
    - https://car.mitre.org/wiki/CAR-2013-04-002
author: juju4
detection:
    selection:
        CommandLine: 
            - arp.exe
            - at.exe
            - attrib.exe
            - cscript.exe
            - dsquery.exe
            - hostname.exe
            - ipconfig.exe
            - mimikatz.exe
            - nbstat.exe
            - net.exe
            - netsh.exe
            - nslookup.exe
            - ping.exe
            - quser.exe
            - qwinsta.exe
            - reg.exe
            - runas.exe
            - sc.exe
            - schtasks.exe
            - ssh.exe
            - systeminfo.exe
            - taskkill.exe
            - telnet.exe
            - tracert.exe
            - wscript.exe
            - xcopy.exe
# others
            - pscp.exe
            - copy.exe
            - robocopy.exe
            - certutil.exe
            - vssadmin.exe
            - powershell.exe
            - wevtutil.exe
            - psexec.exe
            - bcedit.exe
            - wbadmin.exe
            - icacls.exe
            - diskpart.exe
    timeframe: 5m
    condition: selection | count() by MachineName > 5
falsepositives:
    - False positives depend on scripts and administrative tools used in the monitored environment
level: low
---
# Windows Audit Log
logsource:
    product: windows
    service: security
    definition: 'Requirements: Audit Policy : Detailed Tracking > Audit Process creation, Group Policy : Administrative Templates\System\Audit Process Creation'
detection:
    selection:
        EventID: 4688
---
# Sysmon
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1

```








### X-Pack Watcher

```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Quick-Execution-of-a-Series-of-Suspicious-Commands <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "5m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"4688\\" AND CommandLine:(\\"arp.exe\\" \\"at.exe\\" \\"attrib.exe\\" \\"cscript.exe\\" \\"dsquery.exe\\" \\"hostname.exe\\" \\"ipconfig.exe\\" \\"mimikatz.exe\\" \\"nbstat.exe\\" \\"net.exe\\" \\"netsh.exe\\" \\"nslookup.exe\\" \\"ping.exe\\" \\"quser.exe\\" \\"qwinsta.exe\\" \\"reg.exe\\" \\"runas.exe\\" \\"sc.exe\\" \\"schtasks.exe\\" \\"ssh.exe\\" \\"systeminfo.exe\\" \\"taskkill.exe\\" \\"telnet.exe\\" \\"tracert.exe\\" \\"wscript.exe\\" \\"xcopy.exe\\" \\"pscp.exe\\" \\"copy.exe\\" \\"robocopy.exe\\" \\"certutil.exe\\" \\"vssadmin.exe\\" \\"powershell.exe\\" \\"wevtutil.exe\\" \\"psexec.exe\\" \\"bcedit.exe\\" \\"wbadmin.exe\\" \\"icacls.exe\\" \\"diskpart.exe\\"))",\n              "analyze_wildcard": true\n            }\n          },\n          "aggs": {\n            "by": {\n              "terms": {\n                "field": "MachineName.keyword",\n                "size": 10,\n                "order": {\n                  "_count": "desc"\n                },\n                "min_doc_count": 6\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.aggregations.by.buckets.0.doc_count": {\n        "gt": 5\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Quick Execution of a Series of Suspicious Commands\'",\n        "body": "Hits:\\n{{#aggregations.by.buckets}}\\n {{key}} {{doc_count}}\\n{{/aggregations.by.buckets}}\\n",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\ncurl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Quick-Execution-of-a-Series-of-Suspicious-Commands-2 <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "5m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"1\\" AND CommandLine:(\\"arp.exe\\" \\"at.exe\\" \\"attrib.exe\\" \\"cscript.exe\\" \\"dsquery.exe\\" \\"hostname.exe\\" \\"ipconfig.exe\\" \\"mimikatz.exe\\" \\"nbstat.exe\\" \\"net.exe\\" \\"netsh.exe\\" \\"nslookup.exe\\" \\"ping.exe\\" \\"quser.exe\\" \\"qwinsta.exe\\" \\"reg.exe\\" \\"runas.exe\\" \\"sc.exe\\" \\"schtasks.exe\\" \\"ssh.exe\\" \\"systeminfo.exe\\" \\"taskkill.exe\\" \\"telnet.exe\\" \\"tracert.exe\\" \\"wscript.exe\\" \\"xcopy.exe\\" \\"pscp.exe\\" \\"copy.exe\\" \\"robocopy.exe\\" \\"certutil.exe\\" \\"vssadmin.exe\\" \\"powershell.exe\\" \\"wevtutil.exe\\" \\"psexec.exe\\" \\"bcedit.exe\\" \\"wbadmin.exe\\" \\"icacls.exe\\" \\"diskpart.exe\\"))",\n              "analyze_wildcard": true\n            }\n          },\n          "aggs": {\n            "by": {\n              "terms": {\n                "field": "MachineName.keyword",\n                "size": 10,\n                "order": {\n                  "_count": "desc"\n                },\n                "min_doc_count": 6\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.aggregations.by.buckets.0.doc_count": {\n        "gt": 5\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Quick Execution of a Series of Suspicious Commands\'",\n        "body": "Hits:\\n{{#aggregations.by.buckets}}\\n {{key}} {{doc_count}}\\n{{/aggregations.by.buckets}}\\n",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```




