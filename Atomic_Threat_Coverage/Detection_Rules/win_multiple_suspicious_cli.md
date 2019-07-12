| Title                | Quick Execution of a Series of Suspicious Commands                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects multiple suspicious process in a limited timeframe                                                                                                                                           |
| ATT&amp;CK Tactic    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| ATT&amp;CK Technique |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              |  There is no documented Trigger for this Detection Rule yet  |
| Severity Level       | low |
| False Positives      | <ul><li>False positives depend on scripts and administrative tools used in the monitored environment</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://car.mitre.org/wiki/CAR-2013-04-002](https://car.mitre.org/wiki/CAR-2013-04-002)</li></ul>  |
| Author               | juju4 |
| Other Tags           | <ul><li>car.2013-04-002</li><li>car.2013-04-002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Quick Execution of a Series of Suspicious Commands
description: Detects multiple suspicious process in a limited timeframe
status: experimental
references:
    - https://car.mitre.org/wiki/CAR-2013-04-002
author: juju4
modified: 2012/12/11
tags:
    - car.2013-04-002
logsource:
    category: process_creation
    product: windows
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
            - nbtstat.exe
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

```





### es-qs
    
```

```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Quick-Execution-of-a-Series-of-Suspicious-Commands <<EOF\n{\n  "metadata": {\n    "title": "Quick Execution of a Series of Suspicious Commands",\n    "description": "Detects multiple suspicious process in a limited timeframe",\n    "tags": [\n      "car.2013-04-002"\n    ],\n    "query": "CommandLine:(\\"arp.exe\\" \\"at.exe\\" \\"attrib.exe\\" \\"cscript.exe\\" \\"dsquery.exe\\" \\"hostname.exe\\" \\"ipconfig.exe\\" \\"mimikatz.exe\\" \\"nbtstat.exe\\" \\"net.exe\\" \\"netsh.exe\\" \\"nslookup.exe\\" \\"ping.exe\\" \\"quser.exe\\" \\"qwinsta.exe\\" \\"reg.exe\\" \\"runas.exe\\" \\"sc.exe\\" \\"schtasks.exe\\" \\"ssh.exe\\" \\"systeminfo.exe\\" \\"taskkill.exe\\" \\"telnet.exe\\" \\"tracert.exe\\" \\"wscript.exe\\" \\"xcopy.exe\\" \\"pscp.exe\\" \\"copy.exe\\" \\"robocopy.exe\\" \\"certutil.exe\\" \\"vssadmin.exe\\" \\"powershell.exe\\" \\"wevtutil.exe\\" \\"psexec.exe\\" \\"bcedit.exe\\" \\"wbadmin.exe\\" \\"icacls.exe\\" \\"diskpart.exe\\")"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "5m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "CommandLine:(\\"arp.exe\\" \\"at.exe\\" \\"attrib.exe\\" \\"cscript.exe\\" \\"dsquery.exe\\" \\"hostname.exe\\" \\"ipconfig.exe\\" \\"mimikatz.exe\\" \\"nbtstat.exe\\" \\"net.exe\\" \\"netsh.exe\\" \\"nslookup.exe\\" \\"ping.exe\\" \\"quser.exe\\" \\"qwinsta.exe\\" \\"reg.exe\\" \\"runas.exe\\" \\"sc.exe\\" \\"schtasks.exe\\" \\"ssh.exe\\" \\"systeminfo.exe\\" \\"taskkill.exe\\" \\"telnet.exe\\" \\"tracert.exe\\" \\"wscript.exe\\" \\"xcopy.exe\\" \\"pscp.exe\\" \\"copy.exe\\" \\"robocopy.exe\\" \\"certutil.exe\\" \\"vssadmin.exe\\" \\"powershell.exe\\" \\"wevtutil.exe\\" \\"psexec.exe\\" \\"bcedit.exe\\" \\"wbadmin.exe\\" \\"icacls.exe\\" \\"diskpart.exe\\")",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          },\n          "aggs": {\n            "by": {\n              "terms": {\n                "field": "MachineName.keyword",\n                "size": 10,\n                "order": {\n                  "_count": "desc"\n                },\n                "min_doc_count": 6\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.aggregations.by.buckets.0.doc_count": {\n        "gt": 5\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Quick Execution of a Series of Suspicious Commands\'",\n        "body": "Hits:\\n{{#aggregations.by.buckets}}\\n {{key}} {{doc_count}}\\n{{/aggregations.by.buckets}}\\n",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```

```


### splunk
    
```
(CommandLine="arp.exe" OR CommandLine="at.exe" OR CommandLine="attrib.exe" OR CommandLine="cscript.exe" OR CommandLine="dsquery.exe" OR CommandLine="hostname.exe" OR CommandLine="ipconfig.exe" OR CommandLine="mimikatz.exe" OR CommandLine="nbtstat.exe" OR CommandLine="net.exe" OR CommandLine="netsh.exe" OR CommandLine="nslookup.exe" OR CommandLine="ping.exe" OR CommandLine="quser.exe" OR CommandLine="qwinsta.exe" OR CommandLine="reg.exe" OR CommandLine="runas.exe" OR CommandLine="sc.exe" OR CommandLine="schtasks.exe" OR CommandLine="ssh.exe" OR CommandLine="systeminfo.exe" OR CommandLine="taskkill.exe" OR CommandLine="telnet.exe" OR CommandLine="tracert.exe" OR CommandLine="wscript.exe" OR CommandLine="xcopy.exe" OR CommandLine="pscp.exe" OR CommandLine="copy.exe" OR CommandLine="robocopy.exe" OR CommandLine="certutil.exe" OR CommandLine="vssadmin.exe" OR CommandLine="powershell.exe" OR CommandLine="wevtutil.exe" OR CommandLine="psexec.exe" OR CommandLine="bcedit.exe" OR CommandLine="wbadmin.exe" OR CommandLine="icacls.exe" OR CommandLine="diskpart.exe") | eventstats count as val by MachineName| search val > 5
```


### logpoint
    
```
CommandLine IN ["arp.exe", "at.exe", "attrib.exe", "cscript.exe", "dsquery.exe", "hostname.exe", "ipconfig.exe", "mimikatz.exe", "nbtstat.exe", "net.exe", "netsh.exe", "nslookup.exe", "ping.exe", "quser.exe", "qwinsta.exe", "reg.exe", "runas.exe", "sc.exe", "schtasks.exe", "ssh.exe", "systeminfo.exe", "taskkill.exe", "telnet.exe", "tracert.exe", "wscript.exe", "xcopy.exe", "pscp.exe", "copy.exe", "robocopy.exe", "certutil.exe", "vssadmin.exe", "powershell.exe", "wevtutil.exe", "psexec.exe", "bcedit.exe", "wbadmin.exe", "icacls.exe", "diskpart.exe"] | chart count() as val by MachineName | search val > 5
```


### grep
    
```
grep -P '^(?:.*arp\\.exe|.*at\\.exe|.*attrib\\.exe|.*cscript\\.exe|.*dsquery\\.exe|.*hostname\\.exe|.*ipconfig\\.exe|.*mimikatz\\.exe|.*nbtstat\\.exe|.*net\\.exe|.*netsh\\.exe|.*nslookup\\.exe|.*ping\\.exe|.*quser\\.exe|.*qwinsta\\.exe|.*reg\\.exe|.*runas\\.exe|.*sc\\.exe|.*schtasks\\.exe|.*ssh\\.exe|.*systeminfo\\.exe|.*taskkill\\.exe|.*telnet\\.exe|.*tracert\\.exe|.*wscript\\.exe|.*xcopy\\.exe|.*pscp\\.exe|.*copy\\.exe|.*robocopy\\.exe|.*certutil\\.exe|.*vssadmin\\.exe|.*powershell\\.exe|.*wevtutil\\.exe|.*psexec\\.exe|.*bcedit\\.exe|.*wbadmin\\.exe|.*icacls\\.exe|.*diskpart\\.exe)'
```



