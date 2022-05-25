#!/usr/bin/env python3

import scripts.atc_visualizations.visualisation as visualisation
import scripts.atc_visualizations.metrics as metrics
import scripts.atc_visualizations.dashboard as dashboard
import scripts.atc_visualizations.base as base

import argparse
import json
import uuid
import yaml
from yaml.scanner import ScannerError
from os import listdir
from os.path import isfile, join

"""
type: 1
name: 1
title: 1
saved_search_id: 12341234-1234-1234-1234-123412341234
saved_search_name: asd
index: asd
options:
    add_metric:
        - count
        - average:
            field: port

"""


def read_yaml_file(path):
    with open(path, 'r') as f:
        yaml_fields = yaml.load_all(f.read())

    return [x for x in yaml_fields]


class YamlHandler(base.BaseKibana):
    """YamlHandler class"""

    def __init__(self, yaml_path, output_file, omit_kibana, export_type,
                 vis_path="../visualizations/visualizations/"):
        self._export_type = export_type
        if omit_kibana:
            self.omit_kibana()
        self.yamls = read_yaml_file(yaml_path)
        if self._export_type == "api":
            self._results = {"objects": []}
        elif self._export_type == "gui":
            self._results = []
        self._types = [
            "index-pattern", "search", "visualization", "dashboard"
        ]
        self._visualizations = [
            "area", "metric", "pie", "vbar",
        ]
        self._options = [
            "add_metric",
        ]
        self._general_metrics = [
            "average", "count", "max", "min", "median", "percentile-ranks",
            "percentiles", "standard-deviation", "sum", "top-hits",
            "unique-count"
        ]

        self._bucket_names = [
            "date_histogram", "date_range", "filters", "histogram",
            "ip_range", "range", "significant_terms", "terms"
        ]

        self.iter_over_yamls(vis_path=vis_path)
        with open(output_file, 'w') as f:
            json.dump(self._results, f)

    def iter_over_yamls(self, vis_path):
        for yaml_document in self.yamls:
            _type = yaml_document.get('type')
            if not _type:
                raise Exception("Type not defined")
            if _type not in self._types:
                raise Exception(
                    "Defined type (%s) not handled. Available types are %s" %
                    (_type, ", ".join(self._types))
                )

            if _type == "visualization":
                self.visualization_f(yaml_document)
            elif _type == "dashboard":
                self.dashboard(yaml_document, vis_path=vis_path)
            elif _type == "search":
                self.search_f(yaml_document)
            else:
                raise Exception("Not supported yet. Sorry!")

    def append_result(self, result, uuid_=None):
        if self._export_type == "api":
            if uuid_:
                self._results["objects"].append(
                    result.json_export_api(return_dict=True, uuid_=uuid_)
                )
            else:
                self._results["objects"].append(
                    result.json_export_api(return_dict=True)
                )
        elif self._export_type == "gui":
            if uuid_:
                self._results.append(
                    result.json_export_gui(return_dict=True, uuid_=uuid_)
                )
            else:
                self._results.append(
                    result.json_export_gui(return_dict=True)
                )

    def search_f(self, yaml_document):
        self._name = "search"
        _title = yaml_document.get('title')
        _index_name = yaml_document.get('index')
        _columns = yaml_document.get('columns')
        if not _index_name:
            raise Exception("Provide index")
        _query = yaml_document.get('query')
        _language = yaml_document.get('language', "lucene")
        if not _query:
            raise Exception("Saved search without query does not make sense")
        _ss = visualisation.SavedSearchVisualisation(
            title=_title, query=_query, index_name=_index_name,
            columns=_columns, language=_language
        )
        self.append_result(_ss)

    def visualization_f(self, yaml_document, uuid_=None):
        self._name = yaml_document.get('name')
        _title = yaml_document.get('title')
        _saved_search_id = yaml_document.get('saved_search_id')
        _saved_search_name = yaml_document.get('saved_search_name')
        _index_name = yaml_document.get('index')
        if not _saved_search_id and not _saved_search_name and not _index_name:
            raise Exception("""Provide one of these:
  * saved_search_id
  * saved_search_name
  * index
""")
        if not _title:
            raise Exception("No title defined")
        if not self._name:
            raise Exception("No name defined")
        if self._name not in self._visualizations:
            raise Exception(
                ("Type of visualization (%s) not supported. " +
                 "Available types are %s") % (self._name,
                                              ", ".join(self._visualizations))
            )

        if self._name == "area":
            _vis = visualisation.AreaVisualisation(title=_title)
        elif self._name == "metric":
            _vis = visualisation.MetricVisualisation(title=_title)
        elif self._name == "pie":
            _vis = visualisation.PieVisualisation(title=_title)
        elif self._name == "vbar":
            _vis = visualisation.VerticalBarVisualisation(title=_title)
        else:
            _vis = None
        if not _vis:
            raise Exception("Unsupported or invalid visualisation")

        if yaml_document.get('query'):
            _vis.set_query(yaml_document.get('query'))

        if yaml_document.get('labels'):
            self.vis_set_show_labels(self, _vis, yaml_document.get('labels'))

        if _saved_search_name:
            _vis.set_saved_search(saved_search_name=_saved_search_name)

        if _saved_search_id:
            _vis.set_saved_search(saved_search_id=_saved_search_id)

        if _index_name:
            _vis.set_index_search(_index_name)

        if yaml_document.get('metrics'):
            for metric in yaml_document.get('metrics'):
                _metric = None
                if isinstance(metric, str):
                    _metric = self.handle_metric(
                        _vis.metric_id, metric
                    )
                elif isinstance(metric, dict) \
                        and len(metric) == 1:
                    _option_metric_name = [x for x in metric][0]
                    _metric = self.handle_metric(
                        _vis.metric_id, _option_metric_name,
                        args=metric[_option_metric_name]
                    )
                if _metric:
                    _vis.add_metric(_metric)
        self.append_result(_vis, uuid_=uuid_)

    def vis_set_show_labels(self, vis, show_labels):

        if not isinstance(show_labels, bool):
            raise Exception("Provided value is not a bool")

        if isinstance(vis, visualisation.AreaVisualisation):
            print(
                "Warning! Setting labels appearance in Area is not supported"
            )

        elif isinstance(vis, visualisation.MetricVisualisation) \
                or isinstance(vis, visualisation.PieVisualisation):
            if show_labels:
                vis.enable_labels()
            else:
                vis.disable_labels()

    def dashboard(self, yaml_document, vis_path):
        if not yaml_document.get('visualizations'):
            raise Exception("No visualizations, no sense. Provide it!")

        _title = yaml_document.get('title')
        _visualizations = yaml_document.get('visualizations')

        if not _title:
            raise Exception("Provide title")

        if not isinstance(_visualizations, list):
            raise Exception("visualizations var needs to be a list")

        _dashboard = dashboard.KibanaDashboardObject()
        _dashboard.title = _title

        if yaml_document.get('query'):
            _dashboard.set_query(yaml_document.get('query'))

        if yaml_document.get('darktheme'):
            _dashboard.set_dark_theme()

        vis_list = self.load_yamls(vis_path)
        _vis_objects_dict = {}

        self._w, self._h, self._x, self._y = 15, 15, 0, 0

        for object_ in vis_list:
            if object_['title'] \
                    not in yaml_document.get('visualizations'):
                continue
            if object_["type"] == "visualization":
                self.visualization_f(
                    object_, uuid_=object_.get('uuid')
                )
            elif object_["type"] == "search":
                self.search_f(object_)
            _vis_objects_dict[object_.get('title')] = object_
        _counter = 1
        for title in yaml_document.get('visualizations'):
            _dashboard.add_visualization(
                _vis_objects_dict[title], w=self._w, h=self._h,
                x=self._x, y=self._y
            )
            if _counter < 3:
                self._x = self._x + 15
            else:
                self._y = self._y + 15
                self._x = 0
                _counter = 1
                continue
            _counter += 1
        self.append_result(_dashboard)

    def handle_metric(self, id, metric_name, args=None):
        if metric_name not in self._general_metrics \
                and metric_name not in self._bucket_names:
            raise Exception("Metric/bucket not supported")

        if metric_name == "average":
            if not self.allowed_metrics(type="metric", name=metric_name,
                                        visualisation_name=self._name):
                raise Exception(
                    "This metric is not allowed in given visualisation"
                )
            if not args:
                raise Exception("Args required for average metric")
            if not args.get("field"):
                raise Exception("field required")

            return metrics.AverageMetric(id, args.get("field"), args=args)

        elif metric_name == "count":
            if not self.allowed_metrics(type="metric", name=metric_name,
                                        visualisation_name=self._name):
                raise Exception(
                    "This metric is not allowed in given visualisation"
                )
            return metrics.CountMetric(id, args)

        elif metric_name == "max":
            if not self.allowed_metrics(type="metric", name=metric_name,
                                        visualisation_name=self._name):
                raise Exception(
                    "This metric is not allowed in given visualisation"
                )
            if not args:
                raise Exception("Args required for max metric")
            if not args.get("field"):
                raise Exception("field required")

            return metrics.MaxMetric(id, args.get('field'), args=args)

        elif metric_name == "median":
            if not self.allowed_metrics(type="metric", name=metric_name,
                                        visualisation_name=self._name):
                raise Exception(
                    "This metric is not allowed in given visualisation"
                )
            if not args:
                raise Exception("Args required for median metric")
            if not args.get("field"):
                raise Exception("field required")

            return metrics.MedianMetric(id, args.get('field'), args=args)

        elif metric_name == "min":
            if not self.allowed_metrics(type="metric", name=metric_name,
                                        visualisation_name=self._name):
                raise Exception(
                    "This metric is not allowed in given visualisation"
                )
            if not args:
                raise Exception("Args required for min metric")
            if not args.get("field"):
                raise Exception("field required")

            return metrics.MinMetric(id, args.get('field'), args=args)

        elif metric_name == "percentile-ranks":
            if not self.allowed_metrics(type="metric", name=metric_name,
                                        visualisation_name=self._name):
                raise Exception(
                    "This metric is not allowed in given visualisation"
                )
            if not args:
                raise Exception("Args required for percentile-ranks metric")
            if not args.get("field"):
                raise Exception("field required")
            if not args.get('percentile_ranks'):
                raise Exception("percentile_ranks required")

            return metrics.PercentileRanksMetric(
                id, args.get('field'), args=args
            )

        elif metric_name == "percentiles":
            if not self.allowed_metrics(type="metric", name=metric_name,
                                        visualisation_name=self._name):
                raise Exception(
                    "This metric is not allowed in given visualisation"
                )
            if not args:
                raise Exception("Args required for percentiles metric")
            if not args.get("field"):
                raise Exception("field required")

            return metrics.PercentilesMetric(id, args.get('field'), args=args)

        elif metric_name == "standard-deviation":
            if not self.allowed_metrics(type="metric", name=metric_name,
                                        visualisation_name=self._name):
                raise Exception(
                    "This metric is not allowed in given visualisation"
                )
            if not args:
                raise Exception("Args required for standard-deviation metric")
            if not args.get("field"):
                raise Exception("field required")

            return metrics.StandardDeviationMetric(
                id, args.get('field'), args=args
            )

        elif metric_name == "sum":
            if not self.allowed_metrics(type="metric", name=metric_name,
                                        visualisation_name=self._name):
                raise Exception(
                    "This metric is not allowed in given visualisation"
                )
            if not args:
                raise Exception("Args required for sum metric")
            if not args.get("field"):
                raise Exception("field required")

            return metrics.SumMetric(id, args.get('field'), args=args)

        elif metric_name == "top-hits":
            if not self.allowed_metrics(type="metric", name=metric_name,
                                        visualisation_name=self._name):
                raise Exception(
                    "This metric is not allowed in given visualisation"
                )
            if not args:
                raise Exception("Args required for top-hits metric")
            if not args.get("field"):
                raise Exception("field required")
            if not args.get('aggregate_with'):
                raise Exception("aggregate_with required")
            if not args.get('size'):
                raise Exception("size required")
            if not args.get('sort_order'):
                raise Exception("sort_order required")
            if not args.get('sort_field'):
                raise Exception("sort_field required")

            return metrics.TopHitsMetric(
                id, args.get('field'), args.get('aggregate_with'),
                args.get('size'), args.get('sort_order'),
                args.get('sort_field'), args
            )

        elif metric_name == "unique-count":
            if not self.allowed_metrics(type="metric", name=metric_name,
                                        visualisation_name=self._name):
                raise Exception(
                    "This metric is not allowed in given visualisation"
                )
            if not args:
                raise Exception("Args required for unique-count metric")
            if not args.get("field"):
                raise Exception("field required")

            return metrics.UniqueCountMetric(id, args.get('field'), args=args)

        elif metric_name == "terms":
            if not self.allowed_metrics(type="bucket", name=metric_name,
                                        visualisation_name=self._name):
                raise Exception(
                    "This bucket is not allowed in given visualisation"
                )
            if not args:
                raise Exception("Args required for terms bucket")
            if not args.get("field"):
                raise Exception("field required")

            return metrics.TermsBucket(id, args.get('field'), args=args)

    def handle_bucket(self, id, bucket_name, args=None):
        if bucket_name not in self._bucket_names:
            raise Exception("Invalid/unrecognized bucket name")
        self.handle_metric(id=id, metric_name=bucket_name, args=args)

    def allowed_metrics(self, type, name, visualisation_name):
        dictionary_metrics = {
            "pie": ["count", "sum", "top-hits", "unique-count"],
            "metric": ["average", "count", "max", "min", "median",
                       "percentile-ranks", "percentiles", "sum",
                       "top-hits", "unique-count"],
            "area": ["average", "count", "max", "min", "median",
                     "percentile-ranks", "percentiles", "sum",
                     "top-hits", "unique-count"],
            "vbar": ["average", "count", "max", "min", "median",
                     "percentile-ranks", "percentiles", "sum",
                     "top-hits", "unique-count"],
        }
        dictionary_buckets = {
            "pie": [
                "terms",
            ],
            "vbar": [
                "terms",
            ],
        }
        if type.lower() in ["metric", "metrics"]:
            if visualisation_name not in dictionary_metrics.keys():
                raise Exception(
                    "Unable to check if metric is allowed in given " +
                    "visualisation due to unsupported visualisation " +
                    "(%s)." % visualisation_name + "Available visualisations" +
                    ": %s" % ", ".join(self._visualizations)
                )
            if name in dictionary_metrics.get(visualisation_name):
                return True
            return False
        elif type.lower() in ["bucket", "buckets"]:
            if visualisation_name not in dictionary_buckets.keys():
                raise Exception(
                    "Unable to check if bucket is allowed in given " +
                    "visualisation due to unsupported visualisation " +
                    "(%s)." % visualisation_name + "Available visualisations" +
                    ": %s" % ", ".join(self._visualizations)
                )
            if name in dictionary_buckets.get(visualisation_name):
                return True
            return False

    def load_yamls(self, path):
        """Load multiple yamls into list"""

        yamls = [
            join(path, f) for f in listdir(path)
            if isfile(join(path, f))
            if f.endswith('.yaml') or f.endswith('.yml')
        ]

        result = []

        for yaml_item in yamls:
            try:
                with open(yaml_item, 'r') as f:
                    _ = yaml.load_all(f.read())
                    _ = [x for x in _]
                    if len(_) > 1:
                        _ = _[0]
                        _['additions'] = _[1:]
                    else:
                        _ = _[0]
                    _["uuid"] = str(uuid.uuid4())
                    result.append(_)
            except ScannerError:
                raise ScannerError('yaml is bad! %s' % yaml_item)

        return result


def main():
    parser = argparse.ArgumentParser(
        description='Visualisations ATC module a\'ka Atomic Kibana Coverage!'
    )
    parser.add_argument('-i', help="input file location", required=True)
    parser.add_argument('-o', help="output file location", required=True)
    parser.add_argument('-f', help="force to omit kibana", required=False,
                        action='store_true')
    parser.add_argument('-e', help="JSON export type [api/gui]",
                        required=False, default="api", const="gui",
                        action="store_const")
    parser.add_argument('--vis-output', help="Provide where to save output " +
                                             "for visualisations module")

    args = parser.parse_args()
    YamlHandler(args.i, args.o, args.f, args.e)


if __name__ == "__main__":
    main()
