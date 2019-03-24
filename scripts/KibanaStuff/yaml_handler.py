#!/usr/bin/env python3

import yaml
import visualisation
import metrics
import argparse
import json
import dashboard
import base
import uuid

from os import listdir
from os.path import isfile, join

"""
type: 1
name: 1
title: 1
saved_search_id: 12341234-1234-1234-1234-123412341234
saved_search_name: asd
index_name: asd
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


class YamlHandler:
    """YamlHandler class"""

    def __init__(self, yaml_path, output_file):
        self.yamls = read_yaml_file(yaml_path)
        self._results = []
        self._types = [
            "index-pattern", "search", "visualization", "dashboard"
        ]
        self._visualizations = [
            "area", "metric", "pie"
        ]
        self._options = [
            "add_metric",
        ]
        self._general_metrics = [
            "average", "count", "max", "min", "median", "percentile-ranks",
            "percentiles", "standard-deviation", "sum", "top-hits",
            "unique-count"
        ]

        self.iter_over_yamls()
        with open(output_file, 'w') as f:
            json.dump(self._results, f)

    def iter_over_yamls(self):
        for yaml_document in self.yamls:
            print(yaml_document)
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
                self.dashboard(yaml_document)
            else:
                raise Exception("Not supported yet. Sorry!")

    def visualization_f(self, yaml_document, uuid_=None):
        self._name = yaml_document.get('name')
        _title = yaml_document.get('title')
        _saved_search_id = yaml_document.get('saved_search_id')
        _saved_search_name = yaml_document.get('saved_search_name')
        _index_name = yaml_document.get('index_name')
        if not _saved_search_id and not _saved_search_name and not _index_name:
            raise Exception("""Provide one of these:
  * saved_search_id
  * saved_search_name
  * index_name
""")
        _options = yaml_document.get('options')
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
        else:
            _vis = None
        if not _vis:
            raise Exception("Unsupported or invalid visualisation")

        if _saved_search_name:
            _vis.set_saved_search(saved_search_name=_saved_search_name)

        if _saved_search_id:
            _vis.set_saved_search(saved_search_id=_saved_search_id)

        if _index_name:
            _vis.set_index_search(_index_name)

        if _options:
            for option in _options:
                if option not in self._options:
                    raise Exception("Not known option")
                if option == "add_metric":
                    for option_val in _options[option]:
                        _metric = None
                        if isinstance(option_val, str):
                            _metric = self.handle_metric(
                                _vis.metric_id, option_val
                            )
                        elif isinstance(option_val, dict)\
                                and len(option_val) == 1:
                            _option_metric_name = [x for x in option_val][0]
                            _metric = self.handle_metric(
                                _vis.metric_id, _option_metric_name,
                                args=option_val[_option_metric_name]
                            )
                        if _metric:
                            _vis.add_metric(_metric)
        self._results.append(_vis.json_export(return_dict=True, uuid_=uuid_))
        # return _vis

    def dashboard(self, yaml_document):
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
        _dashboard.kibanaSavedObjectMeta = {
          "searchSourceJSON": "{\"query\":{\"query\":\"\"," +
            "\"language\":\"lucene\"},\"filter\":[]}"
        }
        # _dashboard.panelsJSON = base.BasePanelsJson()
        # _dashboard.panelsJSON.gridData = base.BaseGridData()
        # _dashboard.optionsJSON = base.BaseOptionsJson()
        
        # manual definition due to absence of understanding how to do it properly via classes
        # dashboard.py changed accordingly
        _dashboard.optionsJSON = '{ "darkTheme": false }'

        visualization_objects_list = self.load_yamls("/Users/yugoslavskiy/Desktop/re_of_jk_fancy_classes/atomic-threat-coverage/scripts/KibanaStuff/visualizations")

        for visualization in visualization_objects_list:
            if visualization['title'] not in yaml_document.get('visualizations'):
                continue
            _result = self.visualization_f(visualization, uuid_=visualization.get('uuid'))
            _dashboard.add_visualization(visualization)
        self._results.append(_dashboard.json_export(return_dict=True))


    def handle_metric(self, id, metric_name, args=None):
        if metric_name not in self._general_metrics:
            raise Exception("Metric not supported")

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

    def allowed_metrics(self, type, name, visualisation_name):
        dictionary_metrics = {
            "pie": ["count", "sum", "top-hits", "unique-count"],
            "metric": ["average", "count", "max", "min", "median",
                       "percentile-ranks", "percentiles", "sum",
                       "top-hits", "unique-count"],
            "area": ["average", "count", "max", "min", "median",
                     "percentile-ranks", "percentiles", "sum",
                     "top-hits", "unique-count"],
        }
        dictionary_buckets = {
            "pie": [
                "date_histogram", "date_range", "filters", "histogram",
                "ip_range", "range", "significant_terms", "terms"
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
            if f.endswith('.yaml')
            or f.endswith('.yml')
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
    parser = argparse.ArgumentParser(description='Visualizations')
    parser.add_argument('-i', help="input file location", required=True)
    parser.add_argument('-o', help="output file location", required=True)

    args = parser.parse_args()

    YamlHandler(args.i, args.o)


if __name__ == "__main__":
    main()
