| Title                | Renamed Binary                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects the execution of a renamed binary often used by attackers or malware leveraging new Sysmon OriginalFileName datapoint.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1036: Masquerading](https://attack.mitre.org/techniques/T1036)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1036: Masquerading](../Triggers/T1036.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Custom applications use renamed binaries adding slight change to binary name. Typically this is easy to spot and add to whitelist</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://attack.mitre.org/techniques/T1036/](https://attack.mitre.org/techniques/T1036/)</li><li>[https://mgreen27.github.io/posts/2019/05/12/BinaryRename.html](https://mgreen27.github.io/posts/2019/05/12/BinaryRename.html)</li><li>[https://mgreen27.github.io/posts/2019/05/29/BinaryRename2.html](https://mgreen27.github.io/posts/2019/05/29/BinaryRename2.html)</li></ul>  |
| Author               | Matthew Green - @mgreen27 |


## Detection Rules

### Sigma rule

```
title: Renamed Binary
id: 36480ae1-a1cb-4eaa-a0d6-29801d7e9142
status: experimental
description: Detects the execution of a renamed binary often used by attackers or malware leveraging new Sysmon OriginalFileName datapoint.
author: Matthew Green - @mgreen27
date: 2019/06/15
references:
    - https://attack.mitre.org/techniques/T1036/
    - https://mgreen27.github.io/posts/2019/05/12/BinaryRename.html
    - https://mgreen27.github.io/posts/2019/05/29/BinaryRename2.html
tags:
    - attack.t1036
    - attack.defense_evasion
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        OriginalFileName:
            - "cmd.exe"
            - "powershell.exe"
            - "powershell_ise.exe"
            - "psexec.exe"
            - "psexec.c"  # old versions of psexec (2016 seen)
            - "cscript.exe"
            - "wscript.exe"
            - "mshta.exe"
            - "regsvr32.exe"
            - "wmic.exe"
            - "certutil.exe"
            - "rundll32.exe"
            - "cmstp.exe"
            - "msiexec.exe"
            - "7z.exe"
            - "winrar.exe"
    filter:
        Image:
            - '*\cmd.exe'
            - '*\powershell.exe'
            - '*\powershell_ise.exe'
            - '*\psexec.exe'
            - '*\psexec64.exe'
            - '*\cscript.exe'
            - '*\wscript.exe'
            - '*\mshta.exe'
            - '*\regsvr32.exe'
            - '*\wmic.exe'
            - '*\certutil.exe'
            - '*\rundll32.exe'
            - '*\cmstp.exe'
            - '*\msiexec.exe'
            - '*\7z.exe'
            - '*\winrar.exe'
    condition: selection and not filter
falsepositives:
    - Custom applications use renamed binaries adding slight change to binary name. Typically this is easy to spot and add to whitelist
level: medium

```





### splunk
    
```
((OriginalFileName="cmd.exe" OR OriginalFileName="powershell.exe" OR OriginalFileName="powershell_ise.exe" OR OriginalFileName="psexec.exe" OR OriginalFileName="psexec.c" OR OriginalFileName="cscript.exe" OR OriginalFileName="wscript.exe" OR OriginalFileName="mshta.exe" OR OriginalFileName="regsvr32.exe" OR OriginalFileName="wmic.exe" OR OriginalFileName="certutil.exe" OR OriginalFileName="rundll32.exe" OR OriginalFileName="cmstp.exe" OR OriginalFileName="msiexec.exe" OR OriginalFileName="7z.exe" OR OriginalFileName="winrar.exe") NOT ((Image="*\\\\cmd.exe" OR Image="*\\\\powershell.exe" OR Image="*\\\\powershell_ise.exe" OR Image="*\\\\psexec.exe" OR Image="*\\\\psexec64.exe" OR Image="*\\\\cscript.exe" OR Image="*\\\\wscript.exe" OR Image="*\\\\mshta.exe" OR Image="*\\\\regsvr32.exe" OR Image="*\\\\wmic.exe" OR Image="*\\\\certutil.exe" OR Image="*\\\\rundll32.exe" OR Image="*\\\\cmstp.exe" OR Image="*\\\\msiexec.exe" OR Image="*\\\\7z.exe" OR Image="*\\\\winrar.exe")))
```



