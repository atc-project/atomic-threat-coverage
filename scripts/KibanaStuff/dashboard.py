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

    def json_export_api(self, return_dict=False):
        _tmp = {}
        test = self.__dict__
        str_test = str(test)
        _tmp["attributes"] = literal_eval(str_test)
        _tmp["type"] = "dashboard"
        _tmp.pop("_id", None)

        _tmp["attributes"]["panelsJSON"] = json.dumps(
            _tmp["attributes"]["panelsJSON"]
        )
        _tmp["attributes"]["optionsJSON"] = json.dumps(
            _tmp["attributes"]["optionsJSON"]
        )
        _tmp["attributes"]["kibanaSavedObjectMeta"]["searchSourceJSON"] =\
            json.dumps(
                _tmp["attributes"]["kibanaSavedObjectMeta"]["searchSourceJSON"]
        )
        _tmp["attributes"].pop("_id", None)
        _tmp["id"] = str(uuid.uuid4())

        if return_dict:
            return _tmp
        else:
            return json.dumps(_tmp)

    def json_export_gui(self, return_dict=False):
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
        if vis.get('type') == "search":
            vis["uuid"] = vis.get('title').replace(" ", "_")
            _vis = base.BasePanelsJson(vis_uuid=vis["uuid"], type="search")
        elif vis.get('type') in ["visualization", "visualisation"]:
            _vis = base.BasePanelsJson(vis_uuid=vis["uuid"])
        _vis.gridData.x = x
        _vis.gridData.y = y
        _vis.gridData.w = w
        _vis.gridData.h = h
        _vis.gridData.i = str(self._id)
        _vis.panelIndex = str(self._id)
        self.panelsJSON.append(_vis)
        self._id += 1

    def add_saved_search(
            self, saved_search_id=None, saved_search_name=None,
            x=0, y=0, w=20, h=20):

        if not saved_search_id and not saved_search_name:
            raise Exception("What about providing id or name?")

        if saved_search_name and not saved_search_id:
            # Some logic to convert name to id
            pass

        self.add_visualization(vis=saved_search_id, x=x, y=y, w=w, h=h)

    def set_dark_theme(self):
        self.optionsJSON.update({'darkTheme': True})

    def set_query(self, query):
        ssjs = self.kibanaSavedObjectMeta["searchSourceJSON"]
        ssjs["query"]["query"] = str(query)
