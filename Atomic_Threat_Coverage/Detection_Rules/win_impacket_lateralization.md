| Title                | Impacket Lateralization Detection                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects wmiexec/dcomexec/atexec/smbexec from Impacket framework                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1047: Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047)</li><li>[T1175: Component Object Model and Distributed COM](https://attack.mitre.org/techniques/T1175)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1047: Windows Management Instrumentation](../Triggers/T1047.md)</li><li>[T1175: Component Object Model and Distributed COM](../Triggers/T1175.md)</li></ul>  |
| Severity Level       | critical |
| False Positives      | <ul><li>pentesters</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py)</li><li>[https://github.com/SecureAuthCorp/impacket/blob/master/examples/atexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/atexec.py)</li><li>[https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbexec.py)</li><li>[https://github.com/SecureAuthCorp/impacket/blob/master/examples/dcomexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/dcomexec.py)</li></ul>  |
| Author               | Ecco |


## Detection Rules

### Sigma rule

```
title: Impacket Lateralization Detection
id: 10c14723-61c7-4c75-92ca-9af245723ad2
status: experimental
description: Detects wmiexec/dcomexec/atexec/smbexec from Impacket framework
references:
    - https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py
    - https://github.com/SecureAuthCorp/impacket/blob/master/examples/atexec.py
    - https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbexec.py
    - https://github.com/SecureAuthCorp/impacket/blob/master/examples/dcomexec.py
author: Ecco
date: 2019/09/03
logsource:
    category: process_creation
    product: windows
detection:
    selection_other:
        # *** wmiexec.py 
        #    parent is wmiprvse.exe
        #    examples:
        #       cmd.exe /Q /c whoami 1> \\127.0.0.1\ADMIN$\__1567439113.54 2>&1
        #       cmd.exe /Q /c cd  1> \\127.0.0.1\ADMIN$\__1567439113.54 2>&1
        # *** dcomexec.py -object MMC20 
        #   parent is mmc.exe
        #   example:
        #       "C:\Windows\System32\cmd.exe" /Q /c cd  1> \\127.0.0.1\ADMIN$\__1567442499.05 2>&1
        # *** dcomexec.py -object ShellBrowserWindow
        #  runs %SystemRoot%\System32\rundll32.exe shell32.dll,SHCreateLocalServerRunDll {c08afd90-f2a1-11d1-8455-00a0c91f3880} but parent command is explorer.exe
        #  example:
        #   "C:\Windows\System32\cmd.exe" /Q /c cd \ 1> \\127.0.0.1\ADMIN$\__1567520103.71 2>&1
        # *** smbexec.py
        #   parent is services.exe
        #   example:
        #       C:\Windows\system32\cmd.exe /Q /c echo tasklist ^> \\127.0.0.1\C$\__output 2^>^&1 > C:\Windows\TEMP\execute.bat & C:\Windows\system32\cmd.exe /Q /c C:\Windows\TEMP\execute.bat & del C:\Windows\TEMP\execute.bat
        ParentImage:
            - '*\wmiprvse.exe'  # wmiexec
            - '*\mmc.exe'  # dcomexec MMC
            - '*\explorer.exe'  # dcomexec ShellBrowserWindow
            - '*\services.exe'  # smbexec
        CommandLine:
            - '*cmd.exe* /Q /c * \\\\127.0.0.1\\*&1*'
    selection_atexec:
        ParentCommandLine:
            - '*svchost.exe -k netsvcs' # atexec on win10 (parent is "C:\Windows\system32\svchost.exe -k netsvcs")
            - 'taskeng.exe*' # atexec on win7 (parent is "taskeng.exe {AFA79333-694C-4BEE-910E-E57D9A3518F6} S-1-5-18:NT AUTHORITY\System:Service:")
        # cmd.exe /C tasklist /m > C:\Windows\Temp\bAJrYQtL.tmp 2>&1
        CommandLine:
            - 'cmd.exe /C *Windows\\Temp\\*&1'
    condition: (1 of selection_*)
fields:
    - CommandLine
    - ParentCommandLine
tags:
    - attack.lateral_movement
    - attack.t1047
    - attack.t1175
falsepositives:
    - pentesters
level: critical

```





### splunk
    
```
(((ParentImage="*\\\\wmiprvse.exe" OR ParentImage="*\\\\mmc.exe" OR ParentImage="*\\\\explorer.exe" OR ParentImage="*\\\\services.exe") (CommandLine="*cmd.exe* /Q /c * \\\\\\\\127.0.0.1\\\\*&1*")) OR ((ParentCommandLine="*svchost.exe -k netsvcs" OR ParentCommandLine="taskeng.exe*") (CommandLine="cmd.exe /C *Windows\\\\Temp\\\\*&1"))) | table CommandLine,ParentCommandLine
```



