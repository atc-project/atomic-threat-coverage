# Menu

* [Structure](#structure)
* [How to run](#how-to-run)
* [Tips](#tips)
* [Saved Search](#saved-search)
* [Visualizations](#visualizations)
* [Dashboards](#dashboards)

# Structure

Files consist of both required and optional fields. The structure depends on the object you want to define. All the visualizations and saved searches have to be inside `${ATC}/visualizations/visualizations` directory. Dashboards have to be in `${ATC}/visualizations/dashboards` directory. By default, outputs will be saved to `${ATC}/analytics/generated/visualizations/`.

# How to run

## Curl / API

Run the following command in the `${ATC}` directory:

`make visualizations`

Define variables:

```bash
KIBANA_URL="http://<kibana ip/domain>:<kibana port>"
USER=""
PASSWORD=""

```

Then you can use following curl:

```bash
curl -k --user ${USER}:${PASSWORD} -H "Content-Type: application/json"\
  -H "kbn-xsrf: true"\
  -XPOST "${KIBANA_URL}/api/kibana/dashboards/import?exclude=index-pattern&force=true"\
  -d@analytics/generated/visualizations/${FILENAME}.json
```

## WebUI / GUI

Run the following command in the `${ATC}` directory:

`GUI=1 make visualizations`

Next, open Kibana web interface. Navigate to `Management -> Saved Objects` and use `Import` button, select JSON file and correct index ID if there is a non-existing one.

# Tips

* If you choose to create JSON for GUI import (`-e gui` or just `-e`), you can choose index pattern on importing in Kibana.

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
* `index` is the index pattern ID (**not the name** but sometimes that's the same, for example in case of automatically configured by Elastic Beats)
* `query` is a query, just put it in the quotes or double quotes (you have to escape characters in double quotes by youself):
```
query: "\\path\\"

or

query: '\path\'
```

## Visualizations

```yaml
type [required/text]
name [required/text]
title [required/text]
index [*/text]
saved_search_id [*/text]
saved_search_name [*/text]
query [optional/string]
metrics [required/list of metrics]
```

[*] One of them is required

Configurability:

* `type` has to be `visualization`
* `name` is the visualization type, has to be one of `['metric', 'pie', 'vbar']`
* `index` is the index pattern ID (**not the name** but sometimes that's the same, for example in case of automatically configured by Elastic Beats)
* `saved_search_id` is the saved search ID
* `saved_search_name` is the saved search name (we can translate name into ID using Kibana API)
* `title` is the title used inside Kibana
* `query` is a query, just put it in the quotes or double quotes (you have to escape characters in double quotes by youself)
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

> In the vertical bar metric, you can use the `split` parameter with the following available values `x`/`series`/`chart` in order to split X axis, split series or split chart. 
a
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

* `terms` (bucket)

> Used in Pie metric

```yaml
- terms:
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
type [required/text]
name [required/text]
title [required/text]
query [optional/text]
visualizations [required/list of visualizations titles]
```

Configurability:

* `type` has to be `dashboard`
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

# Status: Alpha

Currently we support the next Visualisations in Kibana:

| Name                  | Implemented  |
| --------------------- | ------------ |
| Metric                | Yes          |
| Pie                   | Yes          |
| Vertical Bar          | Yes          |
| Horizontal Bar        |              |
| Area                  |              |
| Line                  |              |
| Data Table            |              |
| Goal                  |              |
| Gauge                 |              |
| Markdown              |              |
| --------------------- | ------------ |
| Heat Map              | Low priority |
| Tag Cloud             | Low priority |
| Region Map            | Low priority |
| Timelion              | Low priority |
| Coordinate Map        | Low priority |
| Visual Builder        | Low priority |
| Controls (E)          | Low priority |
| Vega (E)              | Low priority |

