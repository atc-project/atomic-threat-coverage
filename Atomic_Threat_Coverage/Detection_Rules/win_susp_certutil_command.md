| Title                | Suspicious Certutil Command                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a suspicious Microsoft certutil execution with sub commands like 'decode' sub command, which is sometimes used to decode malicious code with the built-in certutil utility                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1140: Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140)</li><li>[T1105: Remote File Copy](https://attack.mitre.org/techniques/T1105)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1140: Deobfuscate/Decode Files or Information](../Triggers/T1140.md)</li><li>[T1105: Remote File Copy](../Triggers/T1105.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>False positives depend on scripts and administrative tools used in the monitored environment</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://twitter.com/JohnLaTwC/status/835149808817991680](https://twitter.com/JohnLaTwC/status/835149808817991680)</li><li>[https://twitter.com/subTee/status/888102593838362624](https://twitter.com/subTee/status/888102593838362624)</li><li>[https://twitter.com/subTee/status/888071631528235010](https://twitter.com/subTee/status/888071631528235010)</li><li>[https://blogs.technet.microsoft.com/pki/2006/11/30/basic-crl-checking-with-certutil/](https://blogs.technet.microsoft.com/pki/2006/11/30/basic-crl-checking-with-certutil/)</li><li>[https://www.trustedsec.com/2017/07/new-tool-release-nps_payload/](https://www.trustedsec.com/2017/07/new-tool-release-nps_payload/)</li><li>[https://twitter.com/egre55/status/1087685529016193025](https://twitter.com/egre55/status/1087685529016193025)</li><li>[https://lolbas-project.github.io/lolbas/Binaries/Certutil/](https://lolbas-project.github.io/lolbas/Binaries/Certutil/)</li></ul>  |
| Author               | Florian Roth, juju4, keepwatch |
| Other Tags           | <ul><li>attack.s0189</li><li>attack.g0007</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Suspicious Certutil Command
id: e011a729-98a6-4139-b5c4-bf6f6dd8239a
status: experimental
description: Detects a suspicious Microsoft certutil execution with sub commands like 'decode' sub command, which is sometimes used to decode malicious code with
    the built-in certutil utility
author: Florian Roth, juju4, keepwatch
modified: 2019/01/22
references:
    - https://twitter.com/JohnLaTwC/status/835149808817991680
    - https://twitter.com/subTee/status/888102593838362624
    - https://twitter.com/subTee/status/888071631528235010
    - https://blogs.technet.microsoft.com/pki/2006/11/30/basic-crl-checking-with-certutil/
    - https://www.trustedsec.com/2017/07/new-tool-release-nps_payload/
    - https://twitter.com/egre55/status/1087685529016193025
    - https://lolbas-project.github.io/lolbas/Binaries/Certutil/
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - '* -decode *'
            - '* /decode *'
            - '* -decodehex *'
            - '* /decodehex *'
            - '* -urlcache *'
            - '* /urlcache *'
            - '* -verifyctl *'
            - '* /verifyctl *'
            - '* -encode *'
            - '* /encode *'
            - '*certutil* -URL*'
            - '*certutil* /URL*'
            - '*certutil* -ping*'
            - '*certutil* /ping*'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
tags:
    - attack.defense_evasion
    - attack.t1140
    - attack.t1105
    - attack.s0189
    - attack.g0007
falsepositives:
    - False positives depend on scripts and administrative tools used in the monitored environment
level: high

```





### splunk
    
```
(CommandLine="* -decode *" OR CommandLine="* /decode *" OR CommandLine="* -decodehex *" OR CommandLine="* /decodehex *" OR CommandLine="* -urlcache *" OR CommandLine="* /urlcache *" OR CommandLine="* -verifyctl *" OR CommandLine="* /verifyctl *" OR CommandLine="* -encode *" OR CommandLine="* /encode *" OR CommandLine="*certutil* -URL*" OR CommandLine="*certutil* /URL*" OR CommandLine="*certutil* -ping*" OR CommandLine="*certutil* /ping*") | table CommandLine,ParentCommandLine
```



