#!/usr/bin/env python3

import yaml

'''
yaml structure
type: dashboard/visualization/index-patter/search
index: someindex-*
saved_search_name: some_name
saved_search_id: 99812-121-1210212912-11212
options:
    - add_metric: 
        name: string # average
        field: string # @timestamp
???
---
type: dashboard/visualization/index-patter/search
index: someindex-*
saved_search_name: some_name
saved_search_id: 99812-121-1210212912-11212
options:
    - add_metric: 
        name: string # average
        field: string # @timestamp
???
'''


class YamlHandler:
    """YamlHandler class"""

    def __init__(self, yaml_path):
        self.yamls = yaml.loads(yaml_path)

    def check_for_additions(self):
        if self.yaml.get('additions'):
            return True
        else:
            return False

    def create_by_type(self, yml):
        if:
            pass
        elif:
        elif:
        elif:


def main():
    print ("Hello World!")


if __name__ == '__main__':
    main()
