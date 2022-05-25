#!/usr/bin/env python3

from scripts.atcutils import ATCutils

from pathlib import Path


def create_markdown_dirs():
    config = ATCutils.load_config('config.yml')
    base_dir = Path(config.get(
        'md_name_of_root_directory',
        '../Atomic_Threat_Coverage'
    ))

    target_dir_list = [
        'Detection_Rules', 'Logging_Policies', 'Data_Needed',
        'Triggers', 'Enrichments', 'Customers', 'Mitigation_Systems',
        'Mitigation_Policies', 'Hardening_Policies', 'Use_Cases'
    ]

    for item in target_dir_list:
        (base_dir / item).mkdir(parents=True, exist_ok=True)


if __name__ == '__main__':
    create_markdown_dirs()
