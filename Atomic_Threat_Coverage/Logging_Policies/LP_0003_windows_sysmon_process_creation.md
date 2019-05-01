| Title          | LP_0003_windows_sysmon_process_creation                                                                     |
|:---------------|:--------------------------------------------------------------------------------|
| Description    | The process creation event provides extended information  about a newly created process. The full command line provides  context on the process execution. The ProcessGUID field is a  unique value for this process across a domain to make event  correlation easier. The hash is a full hash of the file with  the algorithms in the HashType field.                                                               |
| Default        | Partially (Other)                                                                   |
| Event Volume   | Medium                                                                    |
| EventID        | <ul><li>1</li></ul>         |
| References     | <ul><li>[https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)</li></ul> |



## Configuration

Sysmon event id 1 enabled by default, but include only sha1 hashing function.
Sysmon config to enable md5, sha1, sha256 and imphash functions:
```
<Sysmon schemaversion="4.00">
  <HashAlgorithms>md5,sha1,sha256,imphash</HashAlgorithms>
</Sysmon>
```


