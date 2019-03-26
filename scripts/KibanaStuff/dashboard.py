#!/usr/bin/env python3

import base
import json
import uuid

from ast import literal_eval


class KibanaDashboardObject(base.BaseKibana):
    """Base Kibana DashboardObject"""

    def __init__(self, title=None):

        self.title = str()
        self.description = str()
        self.panelsJSON = list()  # double escaping
        self.optionsJSON = dict()  # double escaping
        self.timeRestore = bool()
        self.kibanaSavedObjectMeta = dict()
        self.version = 1
        self.hits = 0
        self._id = 1

        if title:
            self.title = title

        self.optionsJSON = {'darkTheme': False}
        self.kibanaSavedObjectMeta["searchSourceJSON"] = {
            "query": {
                "query": "",
                "language": "lucene"
            },
            "filter": []
        }

    def validate(self):
        # TODO: Write validate method
        return True

    def __call__(self):
        if self.validate():
            return self.__dict__

    def __repr__(self):
        return str(self.__call__())

    def json_export(self, return_dict=False):
        _tmp = {}
        test = self.__dict__
        str_test = str(test)
        _tmp["_source"] = literal_eval(str_test)
        _tmp["_type"] = "dashboard"
        _tmp.pop("_id", None)

        _tmp["_source"]["panelsJSON"] = json.dumps(
            _tmp["_source"]["panelsJSON"]
        )
        _tmp["_source"]["optionsJSON"] = json.dumps(
            _tmp["_source"]["optionsJSON"]
        )
        _tmp["_source"]["kibanaSavedObjectMeta"]["searchSourceJSON"] =\
            json.dumps(
                _tmp["_source"]["kibanaSavedObjectMeta"]["searchSourceJSON"]
        )
        _tmp["_source"].pop("_id", None)
        _tmp["_id"] = str(uuid.uuid4())

        if return_dict:
            return _tmp
        else:
            return json.dumps(_tmp)

    def add_visualization(self, vis, x=0, y=0, w=20, h=20):
        _vis = base.BasePanelsJson(vis_uuid=vis["uuid"])
        _vis.gridData.x = x
        _vis.gridData.y = y
        _vis.gridData.w = w
        _vis.gridData.h = h
        _vis.gridData.i = self._id
        _vis.panelIndex = self._id
        self.panelsJSON.append(_vis)
        self._id += 1

    def set_dark_theme(self):
        self.optionsJSON.update({'darkTheme': True})

    def set_query(self, query):
        ssjs = self.kibanaSavedObjectMeta["searchSourceJSON"]
        ssjs["query"]["query"] = str(query)
