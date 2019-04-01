#!/usr/bin/env python3

import atc_visualizations.base as base
import json
import uuid

from atc_visualizations.metrics import BaseMetric
from ast import literal_eval

# ########################################################################### #
# ############################ Base Visualisation ########################### #
# ########################################################################### #


class BaseKibanaVisualizationDoc(base.BaseKibanaDoc):
    """Kibana Visualization Doc"""

    def __init__(self, title, type, params_grid=None):

        super().__init__()
        self._meta_data_set = False
        self.metric_id = 1
        self.type = "visualization"
        self.visualization = base.BaseKibanaVisualizationObject(title=title)
        self.visualization.visState = base.BaseKibanaVisState(
            title=title, type=type)
        self.visualization.visState.params = base.BaseKibanaParams(
            type=type, grid=params_grid
        )
        self.visualization.kibanaSavedObjectMeta["searchSourceJSON"] = {
            "index": "",
            "query": {
                "query_string": {
                    "analyze_wildcard": True,
                    "query": "*"
                }
            },
            "filter": []
        }

    def default_axis(self, category_axes_name="CategoryLeftAxis-1"):
        # TODO: Make class for that as well as proper handling in the code
        self.visualization.visState.params.valueAxes.append({
            "id": "ValueAxis-1",
            "name": "LeftAxis-1",
            "type": "value",
            "position": "left",
            "show": True,
            "style": {},
            "scale": {
                "type": "linear",
                "mode": "normal"
            },
            "labels": {
                "show": True,
                "rotate": 0,
                "filter": False,
                "truncate": 100
            },
            "title": {
                "text": "Count"
            }
        }
        )

        # TODO: Make class for that
        self.visualization.visState.params.categoryAxes.append(
            {
                "id": category_axes_name,
                "labels": {
                    "show": True,
                    "truncate": 100
                },
                "position": "bottom",
                "scale": {
                    "type": "linear"
                },
                "show": True,
                "style": {},
                "title": {},
                "type": "category"
            }
        )

    def validate(self):
        supported_vis = ["area", "metric", "pie", "histogram"]
        if self._meta_data_set and super().validate() \
                and self.visualization.visState.type in supported_vis:
            return True
        else:
            return False

    def add_metric(self, metric):
        if not issubclass(metric.__class__, BaseMetric):
            raise Exception("Are you trying to add non-metric?")
        if metric.agg():
            self.visualization.visState.aggs.append(metric.agg())
        if metric.param():
            self.visualization.visState.params.seriesParams.append(
                metric.param()
            )
        self.metric_id += 1

    def json_export_gui(self, return_dict=False, uuid_=None):
        """visState has to be a string with escaped doublequotes"""
        if self.validate():
            # self.updated_at = datetime.datetime.today().isoformat() + "Z"
            # TODO: Find proper way to do below line :))
            tmp_dictionary = literal_eval(str(self.__dict__))
            if uuid_:
                tmp_dictionary["_id"] = uuid_
            else:
                tmp_dictionary["_id"] = str(uuid.uuid4())
            tmp_dictionary["_type"] = tmp_dictionary.pop("type")
            tmp_dictionary["visualization"]["visState"] = json.dumps(
                tmp_dictionary["visualization"]["visState"]
            )
            tmp_dictionary.pop("metric_id", None)
            tmp_dictionary.pop("updated_at", None)
            tmp_dictionary.pop("_meta_data_set", None)
            kbsvd = tmp_dictionary["visualization"]["kibanaSavedObjectMeta"]
            kbsvd["searchSourceJSON"] = json.dumps(
                tmp_dictionary.get("visualization")
                .get("kibanaSavedObjectMeta")
                .get("searchSourceJSON")
            )
            tmp_dictionary["_source"] = tmp_dictionary.pop("visualization")
            if return_dict:
                return tmp_dictionary
            else:
                return json.dumps(tmp_dictionary)
        else:
            raise Exception("Data validation failed")

    def json_export_api(self, return_dict=False, uuid_=None):
        """visState has to be a string with escaped doublequotes"""
        if self.validate():
            # self.updated_at = datetime.datetime.today().isoformat() + "Z"
            # TODO: Find proper way to do below line :))
            tmp_dictionary = literal_eval(str(self.__dict__))
            if uuid_:
                tmp_dictionary["id"] = uuid_
            else:
                tmp_dictionary["id"] = str(uuid.uuid4())
            tmp_dictionary["type"] = tmp_dictionary.pop("type")
            tmp_dictionary["visualization"]["visState"] = json.dumps(
                tmp_dictionary["visualization"]["visState"]
            )
            tmp_dictionary.pop("metric_id", None)
            tmp_dictionary.pop("updated_at", None)
            tmp_dictionary.pop("_meta_data_set", None)
            kbsvd = tmp_dictionary["visualization"]["kibanaSavedObjectMeta"]
            kbsvd["searchSourceJSON"] = json.dumps(
                tmp_dictionary.get("visualization")
                .get("kibanaSavedObjectMeta")
                .get("searchSourceJSON")
            )
            tmp_dictionary["attributes"] = tmp_dictionary.pop("visualization")
            tmp_dictionary["version"] = 1
            if return_dict:
                return tmp_dictionary
            else:
                return json.dumps(tmp_dictionary)
        else:
            raise Exception("Data validation failed")

    def set_index_search(self, index_name):
        if self.check_kibana_vars():
            if self.search_id_of_title_by_type(
                    search_type="index-pattern", search_title=index_name
            ):
                self.visualization\
                    .kibanaSavedObjectMeta["searchSourceJSON"]["index"]\
                    = index_name
                self._meta_data_set = True
            else:
                raise Exception(
                    "Did not find such index name." +
                    " Didn't you forget an asterisk?"
                )
        else:
            self.visualization\
                .kibanaSavedObjectMeta["searchSourceJSON"]["index"]\
                = index_name
            self._meta_data_set = True

    def set_saved_search(self, saved_search_name=None, saved_search_id=None):
        """Provide ID if you know it and don't want to engage kibana"""
        if not saved_search_name and not saved_search_id:
            raise Exception(
                "What's the point of running this method without arguments?"
            )
        _id = ""
        if saved_search_id:
            _id = saved_search_id
        else:
            if not self.check_kibana_vars():
                raise Exception(
                    "Cannot search for an ID if no access to Kibana!"
                )
            _id = self.search_id_of_title_by_type(
                search_type="search", search_title=saved_search_name
            )
        self.visualization.savedSearchId = _id
        self.visualization.kibanaSavedObjectMeta["searchSourceJSON"]\
            .pop("index", None)
        self._meta_data_set = True

    def set_query(self, query):
        ssjs = self.visualization.kibanaSavedObjectMeta["searchSourceJSON"]
        ssjs["query"]["query_string"]["query"] = str(query)

# ########################################################################### #
# ############################ Area Visualisation ########################### #
# ########################################################################### #


class AreaVisualisation(BaseKibanaVisualizationDoc):

    def __init__(self, title):

        super().__init__(title=title, type="area")
        self.default_axis()


# ########################################################################### #
# ############################ Metric Visualisation ######################### #
# ########################################################################### #

class MetricKibanaParams(base.BaseKibanaParams):

    def __init__(self, type=None, grid=None, categoryAxes=None, valueAxes=None,
                 seriesParams=None, addTooltip=None, addLegend=None,
                 legendPosition=None, times=None, addTimeMarker=None):

        super().__init__(
            type=type, grid=grid, categoryAxes=categoryAxes,
            valueAxes=valueAxes, seriesParams=seriesParams,
            addTooltip=addTooltip, addLegend=addLegend,
            legendPosition=legendPosition, times=times,
            addTimeMarker=addTimeMarker)

        self.metric = {
            "percentageMode": False,
            "useRanges": False,
            "colorSchema": "Green to Red",
            "metricColorMode": "None",
            "colorsRange": [
                {
                    "from": 0,
                    "to": 10000
                }
            ],
            "labels": {
                "show": True
            },
            "invertColors": False,
            "style": {
                "bgFill": "#000",
                "bgColor": False,
                "labelColor": False,
                "subText": "",
                "fontSize": 60
            }
        }

    def disable_labels(self):
        self.metric["labels"]["show"] = False

    def enable_labels(self):
        self.metric["labels"]["show"] = True


class MetricVisualisation(BaseKibanaVisualizationDoc):

    def __init__(self, title):

        super().__init__(title=title, type="metric")
        self.visualization.visState.params = MetricKibanaParams(type="metric")

    def disable_labels(self):
        self.visualization.visState.params.disable_labels()

    def enable_labels(self):
        self.visualization.visState.params.enable_labels()


# ########################################################################### #
# ############################ Pie Visualisation ############################ #
# ########################################################################### #


class PieKibanaParams(base.BaseKibanaParams):
    """Pie Kibana Params"""

    def __init__(self, type=None, grid=None, categoryAxes=None, valueAxes=None,
                 seriesParams=None, addTooltip=None, addLegend=None,
                 legendPosition=None, times=None, addTimeMarker=None,
                 isDonut=None, labels_show=None, labels_values=None,
                 labels_last_level=None, labels_truncate=None):

        super().__init__(
            type=type, grid=grid, categoryAxes=categoryAxes,
            valueAxes=valueAxes, seriesParams=seriesParams,
            addTooltip=addTooltip, addLegend=addLegend,
            legendPosition=legendPosition, times=times,
            addTimeMarker=addTimeMarker)

        self.isDonut = True
        self.labels = dict()

        if isDonut:
            self.isDonut = isDonut

        if not labels_show:
            self.labels["show"] = False
        else:
            self.labels["show"] = labels_show

        if not labels_values:
            self.labels["values"] = True
        else:
            self.labels["values"] = labels_values

        if not labels_last_level:
            self.labels["last_level"] = True
        else:
            self.labels["last_level"] = labels_last_level

        if not labels_truncate:
            self.labels["truncate"] = 100
        else:
            self.labels["truncate"] = labels_truncate


class PieVisualisation(BaseKibanaVisualizationDoc):

    def __init__(self, title):

        super().__init__(title=title, type="pie")
        self.visualization.visState.params = PieKibanaParams(type="pie")

    def split_slices(self, bucket):

        _supported_buckets = ["terms", ]

        if not issubclass(bucket.__class__, BaseMetric):
            raise Exception("Are you trying to add non-metric?")

        if bucket not in _supported_buckets:
            raise Exception("Bucket not supported.")

        self.visualization.visState.aggs.append(bucket.agg())
        self.metric_id += 1


# ########################################################################### #
# ############################ Vertical Bar Visualisation ################### #
# ########################################################################### #


class VerticalBarVisualisation(BaseKibanaVisualizationDoc):

    def __init__(self, title):

        super().__init__(
            title=title, type="histogram",
            params_grid={
                "categoryLines": False,
                "style": {
                    "color": "#eee"
                }
            },
        )
        self.default_axis(category_axes_name="CategoryAxis-1")
        self.visualization.visState.params.seriesParams.append({
            "show": "true",
            "type": "histogram",
            "mode": "stacked",
            "data": {
                "label": "",
                "id": "1"
            },
            "valueAxis": "ValueAxis-1",
            "drawLinesBetweenPoints": True,
            "showCircles": True
        })

# ########################################################################### #
# ############################ Vertical Bar Visualisation ################### #
# ########################################################################### #


class SavedSearchVisualisation(BaseKibanaVisualizationDoc):

    def __init__(self, title, query, index_name, columns=[]):
        self.title = title
        self.description = str()
        self.hits = 0
        self.columns = columns
        self.version = 1
        self.kibanaSavedObjectMeta = {}

        self.kibanaSavedObjectMeta["searchSourceJSON"] = \
            {
                "index": str(index_name),
                "highlightAll": True,
                "version": True,
                "query": {
                    "query": str(query),
                    "language": "lucene"
                },
                "filter": []
        }
        self.type = "search"

    def validate(self):
        return True

    def json_export_gui(self, return_dict=False):
        if self.validate():
            tmp_dictionary = literal_eval(str(self.__dict__))
            tmp_dictionary["_type"] = tmp_dictionary.pop("type")
            tmp_dictionary["_source"] = {}
            tmp_dictionary["_source"]["title"] = \
                tmp_dictionary.pop("title")
            tmp_dictionary["_source"]["description"] = \
                tmp_dictionary.pop("description")
            tmp_dictionary["_source"]["hits"] = \
                tmp_dictionary.pop("hits")
            tmp_dictionary["_source"]["version"] = \
                tmp_dictionary.pop("version")
            tmp_dictionary["_source"]["columns"] = \
                json.dumps(tmp_dictionary.pop("columns"))
            tmp_dictionary["_source"]["kibanaSavedObjectMeta"] = \
                tmp_dictionary.pop("kibanaSavedObjectMeta")
            tmp_dictionary["_id"] = tmp_dictionary["_source"]["title"]\
                .replace(" ", "_")

            kbsvd = tmp_dictionary["_source"]["kibanaSavedObjectMeta"]
            kbsvd["searchSourceJSON"] = json.dumps(
                tmp_dictionary.get("_source")
                .get("kibanaSavedObjectMeta")
                .get("searchSourceJSON")
            )

            if return_dict:
                return tmp_dictionary
            else:
                return json.dumps([tmp_dictionary])
        else:
            raise Exception("Data validation failed")

    def json_export_api(self, return_dict=False):
        if self.validate():
            tmp_dictionary = literal_eval(str(self.__dict__))
            tmp_dictionary["type"] = tmp_dictionary.pop("type")
            tmp_dictionary["attributes"] = {}
            tmp_dictionary["attributes"]["title"] = \
                tmp_dictionary.pop("title")
            tmp_dictionary["attributes"]["description"] = \
                tmp_dictionary.pop("description")
            tmp_dictionary["attributes"]["hits"] = \
                tmp_dictionary.pop("hits")
            tmp_dictionary["attributes"]["version"] = \
                tmp_dictionary.pop("version")
            tmp_dictionary["attributes"]["columns"] = \
                json.dumps(tmp_dictionary.pop("columns"))
            tmp_dictionary["attributes"]["kibanaSavedObjectMeta"] = \
                tmp_dictionary.pop("kibanaSavedObjectMeta")
            tmp_dictionary["id"] = tmp_dictionary["attributes"]["title"]\
                .replace(" ", "_")

            kbsvd = tmp_dictionary["attributes"]["kibanaSavedObjectMeta"]
            kbsvd["searchSourceJSON"] = json.dumps(
                tmp_dictionary.get("attributes")
                .get("kibanaSavedObjectMeta")
                .get("searchSourceJSON")
            )

            tmp_dictionary["version"] = 1

            if return_dict:
                return tmp_dictionary
            else:
                return json.dumps([tmp_dictionary])
        else:
            raise Exception("Data validation failed")
