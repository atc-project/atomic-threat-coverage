| Title              | EN0004_enrich_sysmon_event_id_11_with_TargetFilePathFingerprint |
|:-------------------|:-----------------------------------------------------------------------------------------------------------------|
| **Description**    | Enrich Sysmon Event ID 11 (File Create) calculating TargetFilePathFingerprint |
| **Data Needed**    |<ul><li>[DN0015_11_windows_sysmon_FileCreate](../Data_Needed/DN0015_11_windows_sysmon_FileCreate.md)</li></ul> |
| **Data to enrich** |<ul><li>[DN0015_11_windows_sysmon_FileCreate](../Data_Needed/DN0015_11_windows_sysmon_FileCreate.md)</li></ul> |
| **References**     |<ul><li>[https://www.slideshare.net/heirhabarov/hunting-for-privilege-escalation-in-windows-environment](https://www.slideshare.net/heirhabarov/hunting-for-privilege-escalation-in-windows-environment)</li></ul> |
| **Author**         | Teymur Kheirkhabarov           |
| **Requirements**   | None |
| **New fields**     |<ul><li>event_data.TargetFilePathFingerprint</li><li>TargetFilePathFingerprint</li></ul> |


### Config

We can use Logstash to enrich Sysmon Event ID 11, calculating TargetFilePathFingerprint
(md5 hash of computer name and absolute filepath) via Ruby filter plugin.
Here is the config example:

```
filter {
  # calculating filepath fingerprint
  if [event_id] == 11 and ([event_data][TargetFilename] =~ ".exe" or [event_data][TargetFilename] =~ ".dll" [event_data][TargetFilename] =~ ".sys" ) {
    ruby { 
      code => "
              require 'digest'
              md5 = Digest::MD5.new
              md5.update event.get('[computer_name]').downcase+event.get('[event_data][TargetFilename]').downcase
              event.set('[event_data][TargetFilePathFingerprint]', md5.hexdigest)
              "
    }
  }
}
```
