#!/usr/bin/env python3

try:
    from scripts.atcutils import ATCutils
    from scripts.react_mapping import ra_mapping
    from scripts.update_react_mapping import UpdateReactMapping
except:
    from atcutils import ATCutils
    from react_scripts.react_mapping import ra_mapping
    from react_scripts.update_react_mapping import UpdateReactMapping

from os import listdir
from os.path import isfile, join
import json

ATCconfig = ATCutils.load_config("config.yml")
filename = 'react_navigator_profile.json'
directory = ATCconfig.get('exported_analytics_directory')

NAVIGATOR_TEMPLATE = {
    "name": "RE&CT Enterprise Matrix",
    "version": "2.2",
    "domain": "atc-react",
    "description": "Response Stages and Response Actions, colorized by Categories",
    "sorting": 2,
    "viewMode": 0,
    "hideDisabled": True,
    "techniques": [],
    "gradient": {
        "colors": [
            "#ff6666",
            "#ffe766",
            "#8ec843"
        ],
        "minValue": 0,
        "maxValue": 100
    },
    "legendItems": [  # thanks, Olaf!
        {
            "label": "General cagetory",
            "color": "#FFD300"
        },
        {
            "label": "Network cagetory",
            "color": "#ABC530"
        },
        {
            "label": "Email cagetory",
            "color": "#01C26D"
        },
        {
            "label": "File cagetory",
            "color": "#007B84"
        },
        {
            "label": "Process cagetory",
            "color": "#075190"
        },
        {
            "label": "Configuration cagetory",
            "color": "#86308C"
        },
        {
            "label": "Identity cagetory",
            "color": "#482569"
        },
    ],
    "showTacticRowBackground": False,
    "tacticRowBackground": "#dddddd",
    "selectTechniquesAcrossTactics": True
}

# thanks again, Olaf!
category_colors = {
    "General": '#ffd300',
    "Network": '#abc530',
    "Email": '#01c26d',
    "File": '#007b84',
    "Process": '#075190',
    "Configuration": '#86308c',
    "Identity": '#482569'
}


class GenerateNavigator:

    def __init__(self):

        UpdateReactMapping()

        response_actions = []
        for ra_id, ra_name in ra_mapping.items():
            ra_color = ""
            category_score = int(ra_id[3:6])
            ra_category = ATCutils.get_ra_category(ra_id)

            for category_name, category_color in category_colors.items():
                if ra_category == category_name:
                    ra_color = category_color
                    break

            response_actions.append({
                "techniqueID": ra_id,
                "color": ra_color,
                "score": category_score,        # for sorting
            })

        NAVIGATOR_TEMPLATE['techniques'] = response_actions

        with open(directory + '/' + filename, 'w') as fp:
            json.dump(NAVIGATOR_TEMPLATE, fp)
        print(f'[+] Created {filename}')
