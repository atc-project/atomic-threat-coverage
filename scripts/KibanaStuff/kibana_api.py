#!/bin/env python3

# import requests
# from elasticsearch import Elasticsearch
from elasticsearch.client import Elasticsearch as CES
from pprint import pprint


class KibanaBaseModel():
    def __init__(self, rdata):
        self.id = rdata.get('_id').split(
            ':')[1] if ':' in rdata.get('_id') else None
        self.raw_id = rdata.get('_id')
        self.index = rdata.get('_index')
        self.data = rdata.get('_source')
        self.raw_data = rdata


class Visualizations(KibanaBaseModel):
    """Simple visualization class"""

    def __init__(self, rdata):
        super().__init__(rdata)
        if rdata.get('_source'):
            if rdata['_source'].get('visualization'):
                self.title = rdata['_source']['visualization'].get('title')


class Dashboards(KibanaBaseModel):
    """Simple visualization class"""

    def __init__(self, rdata):
        super().__init__(rdata)
        if rdata.get('_source'):
            if rdata['_source'].get('dashboard'):
                self.title = rdata['_source']['dashboard'].get('title')


class KibanaAPI():

    visualizations = []
    dashboards = []

    def __init__(self, es):

        self.search_limit_size = 10000  # 10000 is MAX

        if isinstance(es, CES):
            self.es = es
        else:
            raise Exception("Elasticsearch client class NOT provided")

    def get_all(self):
        """Get all saved objects and put them into visualization/dashboards"""

        r = self.es.search(
            index='.kibana*', doc_type='',
            body={'query': {'match_all': {}}},
            size=self.search_limit_size,
        )

        for obj in r['hits']['hits']:
            if obj.get('_source'):
                if obj['_source'].get('type'):
                    _type = obj['_source']['type']
                    if _type == 'visualization':
                        self.visualizations.append(Visualizations(obj))
                    if _type == 'dashboard':
                        self.dashboards.append(Dashboards(obj))

    def push_object(self, data):

        pass


if __name__ == "__main__":
    from elasticsearch import Elasticsearch as ES

    es = ES(['http://localhost:9200'])
    kapi = KibanaAPI(es)

    kapi.get_all()

    print("Dashboards: ")
    for dashboard in kapi.dashboards:
        print(dashboard.title)

    print("\nVisualizations:")
    for vis in kapi.visualizations:
        if "Area #1" == vis.title:
            import json
            print(vis.title)
            visState = json.loads(vis.data["visualization"]["visState"])
            pprint(visState)
            print("\n\n")
