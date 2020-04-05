| Title              | EN_0002_enrich_sysmon_event_id_1_with_parent_info |
|:-------------------|:-----------------------------------------------------------------------------------------------------------------|
| **Description**    | Enrich Sysmon Event ID 1 (Process Create) with Parent Integrity Level,  Parent User and Parent of Parent Image fields. |
| **Data Needed**    |<ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul> |
| **Data to enrich** |<ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul> |
| **References**     |<ul><li>[https://www.slideshare.net/heirhabarov/hunting-for-privilege-escalation-in-windows-environment](https://www.slideshare.net/heirhabarov/hunting-for-privilege-escalation-in-windows-environment)</li></ul> |
| **Author**         | Teymur Kheirkhabarov           |
| **Requirements**   |<ul><li>[EN_0001_cache_sysmon_event_id_1_info](../Enrichments/EN_0001_cache_sysmon_event_id_1_info.md)</li></ul>> |
| **New fields**     |<ul><li>event_data.ParentIntegrityLevel</li><li>event_data.ParentUser</li><li>event_data.ParentOfParentImage</li><li>ParentIntegrityLevel</li><li>ParentUser</li><li>ParentOfParentImage</li></ul> |


### Config

We can use Logstash to enrich Sysmon Event ID 1 with data cached in Memcached. 
Here is the config example:

```
filter {
  # Get previously cached information about parent process from cache to enrich process creation events (event id 1)
  if [source_name] == "Microsoft-Windows-Sysmon" and [event_id] == 1 and [event_data][ParentProcessGuid] {
    # Enrich event with additional information about process
    memcached {
      # get info from cache
      hosts => ["127.0.0.1:11211"]
      get => {
        "%{computer_name}_%{[event_data][ParentProcessGuid]}" => "[@metadata][processinfo]"
      }
    }
    if [@metadata][processinfo] {
      kv {
        source => "[@metadata][processinfo]"
        target => "[@metadata][processinfo]"
        field_split => ","
        value_split => "="
      }
      if [@metadata][processinfo][ParentImage] {
        mutate {
          add_field => { "[event_data][ParentIntegrityLevel]" => "%{[@metadata][processinfo][IntegrityLevel]}" }
          add_field => { "[event_data][ParentUser]" => "%{[@metadata][processinfo][User]}" }
          add_field => { "[event_data][ParentOfParentImage]" => "%{[@metadata][processinfo][ParentImage]}" }
        }
      }
    }
  }
}
```
