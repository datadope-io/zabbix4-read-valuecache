# Zabbix v4 value cache analyzer

Application to look inside of the zabbix_server memory to get which data is being stored in the value cache.

In the ``-p`` parameter put the PID of the zabbix_server parent process.

If ``-analyze-items`` is enabled, it will scan all the value cache (the ``items`` hashset) to get which item ids are stored.
This could be expensive (~8s for 300k items.num_slots).

This will show the ``-number-of-top-items`` using most values and a histogram of how many values have each item.
The histogram will show only the itemids if the number is below ``-histogram-max-itemids``.

Example histogram:
```
    397 -   794: 76 items (11263010, 10905062, 11782312, 11780196, 8494850, 11781925, 9173251, ...)
```
It should be read as: there are 76 items which have between 397 and 794 values. The list between brackets are some of the
item ids in that group.

If ``-show-items-details`` is enabled, show how many values has stored each item id.


Example:
```
# procmem-go -p 1115306 -analyze-items -show-items-details
-- zbx_vc_cache_t --
hits: 354133020315
misses: 563811816
mode: 0
mode_time: 1684493896
last_warning_time: 1684493756
items.num_slots: 298153
items.num_data: 127284
strpool.num_slots: 17431
strpool.num_data: 10206

Top 10 items by number of values stored:
  4781209: 3580
  10771467: 2903
  11805164: 2689
  9741033: 2682
  9741013: 2680
  9741016: 2679
  11805160: 2679
  9741036: 2678
  9741037: 2676
  9741005: 2676

Histogram, format: value range: N values (item ids)
      0 -   397: 103148 items (10189858, 9540928, 8366577, 2377114, 8309433, 996421, 10922182, 916408, 12000161, 850179, ...)
    397 -   794: 76 items (11780015, 7640584, 10905060, 11774248, 11775473, 11780025, 11575629, 11780615, 11262997, 11780605, ...)
    794 -  1191: 9 items (1006320, 11773912, 10254382, 10796931, 11778314, 9305245, 10757228, 11781640, 11199034)
   1191 -  1588: 62 items (11776488, 11776648, 11966214, 11776489, 11776543, 11774835, 11776490, 11776545, 11776479, 11776556, ...)
   1588 -  1985: 95 items (11775721, 11775817, 11780368, 11775650, 11779392, 11775647, 11780203, 11775809, 11775641, 11775338, ...)
   1985 -  2382: 347 items (11780520, 11780522, 11781839, 11779925, 11780602, 11781881, 11783972, 11780521, 11779942, 11774233, ...)
   2382 -  2779: 11 items (11805158, 9741016, 9741005, 11805160, 9741036, 10757236, 9741033, 11805164, 9741037, 9741013, ...)
   2779 -  3176: 1 items (10771467)
   3176 -  3573: 0 items
   3573 -  3970: 1 items (4781209)
