| Title              | EN_0005_cache_TargetFilePathFingerprint_from_enriched_sysmon_event_id_11 |
|:-------------------|:-----------------------------------------------------------------------------------------------------------------|
| **Description**    | Cache field "TargetFilePathFingerprint" from enriched Sysmon Event ID 11 (File Create). |
| **Data Needed**    |<ul><li>[DN_0015_11_windows_sysmon_FileCreate](../Data_Needed/DN_0015_11_windows_sysmon_FileCreate.md)</li></ul> |
| **Data to enrich** | None |
| **References**     |<ul><li>[https://www.slideshare.net/heirhabarov/hunting-for-privilege-escalation-in-windows-environment](https://www.slideshare.net/heirhabarov/hunting-for-privilege-escalation-in-windows-environment)</li></ul> |
| **Author**         | Teymur Kheirkhabarov           |
| **Requirements**   |<ul><li>[EN_0004_enrich_sysmon_event_id_11_with_TargetFilePathFingerprint](../Enrichments/EN_0004_enrich_sysmon_event_id_11_with_TargetFilePathFingerprint.md)</li></ul>> |
| **New fields**     | None |


### Config

We can use Logstash to cache data in Memcached. 
Here is the config example:

```
filter {
  # cahce TargetFilePathFingerprint field 
  if [event_id] == 11 and ([event_data][TargetFilename] =~ ".exe" or [event_data][TargetFilename] =~ ".dll" [event_data][TargetFilename] =~ ".sys" ) {
    memcached { 
      hosts => ["127.0.0.1:11211"]
      set => {
        "[@metadata][processinfo]" => "%{[event_data][TargetFilePathFingerprint]}"
      }
      ttl => 86400 # 24 hours
    }
  }
}
```
