| Title                | Quick Execution of a Series of Suspicious Commands                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects multiple suspicious process in a limited timeframe                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul></ul>  |
| ATT&amp;CK Technique | <ul></ul>                             |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              |  There is no Trigger for this technique yet.  |
| Severity Level       | low                                                                                                                                                 |
| False Positives      | <ul><li>False positives depend on scripts and administrative tools used in the monitored environment</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://car.mitre.org/wiki/CAR-2013-04-002](https://car.mitre.org/wiki/CAR-2013-04-002)</li></ul>                                                          |
| Author               | juju4                                                                                                                                                |
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

```


### graylog
    
```

```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*arp\\.exe|.*at\\.exe|.*attrib\\.exe|.*cscript\\.exe|.*dsquery\\.exe|.*hostname\\.exe|.*ipconfig\\.exe|.*mimikatz\\.exe|.*nbtstat\\.exe|.*net\\.exe|.*netsh\\.exe|.*nslookup\\.exe|.*ping\\.exe|.*quser\\.exe|.*qwinsta\\.exe|.*reg\\.exe|.*runas\\.exe|.*sc\\.exe|.*schtasks\\.exe|.*ssh\\.exe|.*systeminfo\\.exe|.*taskkill\\.exe|.*telnet\\.exe|.*tracert\\.exe|.*wscript\\.exe|.*xcopy\\.exe|.*pscp\\.exe|.*copy\\.exe|.*robocopy\\.exe|.*certutil\\.exe|.*vssadmin\\.exe|.*powershell\\.exe|.*wevtutil\\.exe|.*psexec\\.exe|.*bcedit\\.exe|.*wbadmin\\.exe|.*icacls\\.exe|.*diskpart\\.exe)'
```



