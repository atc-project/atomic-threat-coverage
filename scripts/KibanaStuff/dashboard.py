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
        self.optionsJSON = str()  # double escaping
        self.timeRestore = bool()
        self.kibanaSavedObjectMeta = dict()
        self.version = 1
        self.hits = 0
        self._id = 1

        if title:
            self.title = title

    #def validate(self):
    #    # TODO: Write validate method
    #    return True

    #def __call__(self):
    #    if self.validate():
    #        return self.__dict__

    def __repr__(self):
        return str(self.__call__())

    def json_export(self, return_dict=False):
        _tmp = {}
        test = self.__dict__
        str_test = str(test)
        _tmp["attributes"] = literal_eval(str_test)
       # _tmp["attributes"] = literal_eval(str(self.__dict__))
        _tmp["type"] = "dashboard"
        _tmp["version"] = "1"
        
        # 23.03.2010
        # temporarly changed due to wrong level of presence in final JSON and wrong value (should be uuid)
        #_tmp.pop("_id", None)

        _tmp["attributes"]["panelsJSON"] = json.dumps(_tmp["attributes"]["panelsJSON"])
        #_tmp["attributes"]["optionsJSON"] = json.dumps(_tmp["attributes"]["optionsJSON"])
        
        # 23.03.2010
        # temporarly changed due to hardcoded definition in yaml_handler
        _tmp["attributes"]["optionsJSON"] = _tmp["attributes"]["optionsJSON"]
        _tmp["id"] = str(uuid.uuid4())
        
        if return_dict:
            return _tmp
        else:
            return json.dumps(_tmp)

    def add_visualization(self, vis, x=0, y=0, w=0, h=0):
        _vis = base.BasePanelsJson(vis_uuid=vis["uuid"])
        _vis.gridData.x = x
        _vis.gridData.y = y
        _vis.gridData.w = w
        _vis.gridData.h = h
        _vis.gridData.i = self._id
        _vis.panelIndex = self._id
        # print(type(self.panelsJSON))
        self.panelsJSON.append(_vis)
        self._id += 1

