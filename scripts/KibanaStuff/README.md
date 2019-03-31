# Menu

* [Structure](#structure)
* [Tips](#tips)
* [Saved Search](#saved-search)
* [Visualizations](#visualizations)
* [Dashboards](#dashboards)

# Structure

Files consist of both required and optional fields. The structure depends on the object you want to define. All the visualizations and saved searches have to be inside `visualizations` directory. Dashboards can be anywhere but to keep it simple, just put it `dashboards` directory.

# Tips

* If you choose to create JSON for GUI import (`-e gui` or just `-e`), you can choose index pattern on importing in Kibana

## Saved Search

```yaml
type [required]
title [required]
index [required]
query [required]
```

Configurability:

* `type` has to be `search`
* `title` is a name which you will see in Kibana as well as the ID of the
* `index` is the index pattern ID (**not the name** but sometimes that's the same)
* `query` is a query, just put it in the quotes or double quotes (you have to escape characters in double quotes by youself)

## Visualizations

```yaml
type [required]
name [required]
title [required]
index [1 of 3/text]
saved_search_id [1 of 3/text]
saved_search_name [1 of 3/text]
query [optional/string]
metrics [required/list of metrics]
```

Configurability:

* `type` has to be `visualization`
* `name` is the visualization type, has to be one of `['metric', 'pie', 'vbar']`
* `index` is the index pattern ID (**not the name** but sometimes that's the same)
* `saved_search_id` is the saved search ID
* `saved_search_name` is the saved search name (we can translate name into ID using Kibana API)
* `title` is the title used inside Kibana
*  `query` is a query, just put it in the quotes or double quotes (you have to escape characters in double quotes by youself)
* `metrics` contains a list of metrics (they are described below)

| Field               | Available values            |
|---------------------|-----------------------------|
| `type`              | `visualization`             |
| `name`              | `['metric', 'pie', 'vbar']` |
| `index`             | `some-index-id`             |
| `saved_search_id`   | `some-saved-search-id`      |
| `saved_search_name` | `some-saved-search-name`    |
| `title`             | `some title`                |
| `query`             | `any query in lucene`       |
| `metrics`           | `list of metrics`           |

### Metrics

> In the vertical bar metric, you can use the `split` parameter with the following available values `x`/`series`/`chart` in order to split X axis, split series or chart. 

* `count`

```yaml
- count:
    enabled: [optional/bool]
    label: [optional/text]
```

| Field     | Available values    |
|-----------|---------------------|
| `enabled` | `true`/`false`      |
| `label`   | `any string`        |

* `average`

```yaml
- average:
    field: [required/text]
    enabled: [optional/bool]
    label: [optional/text]
```

| Field     | Available values    |
|-----------|---------------------|
| `field`   | `field as a string` |
| `enabled` | `true`/`false`      |
| `label`   | `any string`        |


* `max`

```yaml
- max:
    field: [required/text]
    enabled: [optional/bool]
    label: [optional/text]
```

| Field     | Available values    |
|-----------|---------------------|
| `field`   | `field as a string` |
| `enabled` | `true`/`false`      |
| `label`   | `any string`        |


* `median`

```yaml
- median:
    field: [required/text]
    enabled: [optional/bool]
    label: [optional/text]
```

| Field     | Available values    |
|-----------|---------------------|
| `field`   | `field as a string` |
| `enabled` | `true`/`false`      |
| `label`   | `any string`        |


* `min`

```yaml
- min:
    field: [required/text]
    enabled: [optional/bool]
    label: [optional/text]
```

| Field     | Available values    |
|-----------|---------------------|
| `field`   | `field as a string` |
| `enabled` | `true`/`false`      |
| `label`   | `any string`        |


* `percentile_ranks`

```yaml
- percentile_ranks:
    field: [required/text]
    percentile_ranks: [required/list of integers]
    enabled: [optional/bool]
    label: [optional/text]
```

| Field                | Available values    |
|----------------------|---------------------|
| `field`              | `field as a string` |
| `percentile_ranks`   | `[1, 2, 9, 22, 99]` |
| `enabled`            | `true`/`false`      |
| `label`              | `any string`        |


* `percentiles`

```yaml
- percentiles:
    field: [required/text]
    percents: [optional/list of integers]
    enabled: [optional/bool]
    label: [optional/text]
```

| Field                | Available values             |
|----------------------|------------------------------|
| `field`              | `field as a string`          |
| `percentes`          | `[1, 5, 25, 50, 75, 95, 99]` |
| `enabled`            | `true`/`false`               |
| `label`              | `any string`                 |

* `standard_deviation`

```yaml
- standard_deviation:
    field: [required/text]
    enabled: [optional/bool]
    label: [optional/text]
```

| Field     | Available values    |
|-----------|---------------------|
| `field`   | `field as a string` |
| `enabled` | `true`/`false`      |
| `label`   | `any string`        |

* `sum`

```yaml
- sum:
    field: [required/text]
    enabled: [optional/bool]
    label: [optional/text]
```

| Field     | Available values    |
|-----------|---------------------|
| `field`   | `field as a string` |
| `enabled` | `true`/`false`      |
| `label`   | `any string`        |

* `top_hits`

```yaml
- top_hits:
    field: [required/text]
    aggregate_with: [required/text]
    size: [required/integer]
    sort_order: [required/text]
    sort_field: [required/text]
    enabled: [optional/bool]
    label: [optional/text]
```

| Field              | Available values    |
|--------------------|---------------------|
| `field`            | `field as a string` |
| `aggregate_with`   | `concat`            |
| `size`             | `5`                 |
| `sort_order`       | `asc`, `desc`       |
| `sort_field`       | `field as a string` |
| `enabled`          | `true`/`false`      |
| `label`            | `any string`        |

* `unique_count`

```yaml
- unique_count:
    field: [required/text]
    enabled: [optional/bool]
    label: [optional/text]
```

| Field     | Available values    |
|-----------|---------------------|
| `field`   | `field as a string` |
| `enabled` | `true`/`false`      |
| `label`   | `any string`        |

# Dashboards


```yaml
type [required]
name [required]
title [required]
query [optional/string]
visualizations [required/list of visualizations titles]
```

Configurability:

* `type` has to be `visualization`
* `name` for now it's the same as title
* `title` is the title used inside Kibana
* `darktheme` defines if dark theme should be used
* `query` is a query, just put it in the quotes or double quotes (you have to escape characters in double quotes by youself)
* `visualizations` contains a list of metrics (they are described below)

| Field               | Available values            |
|---------------------|-----------------------------|
| `type`              | `visualization`             |
| `name`              | `some title`                |
| `title`             | `some title`                |
| `darktheme`         | `true`/`false`              |
| `query`             | `any query in lucene`       |
| `visualizations`    | `list of visualizations`    |
