| Title            | LP_0007_windows_sysmon_ProcessAccess                                                                     |
|:-----------------|:--------------------------------------------------------------------------------|
| **Description**  | The process accessed event reports when a process opens another process,  an operation that’s often followed by information queries or reading and writing the address  space of the target process. This enables detection of hacking tools that read the memory  contents of processes like Local Security Authority (Lsass.exe) in order to steal credentials for use in Pass-the-Hash  attacks. Enabling it can generate significant amounts of logging if there are diagnostic utilities active  that repeatedly open processes to query their state, so it generally should only be done so with filters  that remove expected accesses.                                                               |
| **Default**      | Not configured                                                                   |
| **Event Volume** | High                                                                    |
| **EventID**      | <ul><li>10</li></ul>         |
| **References**   | <ul><li>[https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)</li></ul> |



## Configuration

Sysmon event id 10 is disabled by default. 
It can be enabled by specyfying configuration
However due to high level of produced logs it should be filtred with configuration file
Sample configuration:
```
  <ProcessAccess onmatch="include">
    <TargetImage condition="is">C:\Windows\system32\lsass.exe</TargetImage>
  </ProcessAccess>
  <ProcessAccess onmatch="exclude">
    <SourceImage condition="is">C:\windows\system32\wbem\wmiprvse.exe</SourceImage>
    <SourceImage condition="is">C:\windows\system32\svchost.exe</SourceImage>
  </ProcessAccess>
```


