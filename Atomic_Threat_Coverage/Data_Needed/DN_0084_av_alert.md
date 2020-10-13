| Title              | DN_0084_av_alert       |
|:-------------------|:------------------|
| **Description**    | Anti-virus alert |
| **Logging Policy** | <ul><li> Not existing </li></ul> |
| **References**     | <ul><li>[None](None)</li></ul> |
| **Platform**       | antivirus    |
| **Type**           | None        |
| **Channel**        | None     |
| **Provider**       | None    |
| **Fields**         | <ul><li>Hostname</li><li>Signature</li><li>AlertTitle</li><li>Category</li><li>Severity</li><li>Sha1</li><li>FileName</li><li>FilePath</li><li>IpAddress</li><li>UserName</li><li>UserDomain</li><li>FileHash</li><li>Hashes</li><li>Imphash</li><li>Sha256hash</li><li>Sha1hash</li><li>Md5hash</li></ul> |


## Log Samples

### Raw Log

```
{
  "AlertTime":"2017-01-23T07:32:54.1861171Z",
  "ComputerDnsName":"desktop-bvccckk",
  "AlertTitle":"Suspicious PowerShell commandline",
  "Category":"SuspiciousActivity",
  "Severity":"Medium",
  "AlertId":"636207535742330111_-1114309685",
  "Actor":null,
  "LinkToWDATP":"https://securitycenter.windows.com/alert/636207535742330111_-1114309685",
  "IocName":null,
  "IocValue":null,
  "CreatorIocName":null,
  "CreatorIocValue":null,
  "Sha1":"69484ca722b4285a234896a2e31707cbedc59ef9",
  "FileName":"powershell.exe",
  "FilePath":"C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0",
  "IpAddress":null,
  "Url":null,
  "IoaDefinitiondId":"7f1c3609-a3ff-40e2-995b-c01770161d68",
  "UserName":null,
  "AlertPart":0,
  "FullId":"636207535742330111_-1114309685:9DE735BA9FF87725E392C6DFBEB2AF279035CDE229FCC00D28C0F3242C5A50AF",
  "LastProcessedTimeUtc":"2017-01-23T11:33:45.0760449Z",
  "ThreatCategory":null,
  "ThreatFamily":null,
  "ThreatName":null,
  "RemediationAction":null,
  "RemediationIsSuccess":null,
  "Source":"Windows Defender ATP",
  "Md5":null,
  "Sha256":null,
  "WasExecutingWhileDetected":null,
  "FileHash":"69484ca722b4285a234896a2e31707cbedc59ef9",
  "IocUniqueId":"9DE735BA9FF87725E392C6DFBEB2AF279035CDE229FCC00D28C0F3242C5A50AF"
}

```




