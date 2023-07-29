import yaml
import os
import get_tests_dict

import requests

MASVS = None

def retrieve_masvs(version="latest"):
    global MASVS
    url = f"https://github.com/OWASP/owasp-masvs/releases/{version}/download/OWASP_MASVS.yaml"
    response = requests.get(url)
    content = response.content
    MASVS = yaml.safe_load(content)
    return MASVS

def get_masvs_groups():
    groups = {}
    for group in MASVS['groups']:
        group_id = group['id']
        groups[group_id] = {'id': group_id, 'title': group['title']}
    return groups

def add_control_row(checklist, control):
    checklist_row = {
        'MASVS-ID': control['id'],
        'path': f"/MASVS/controls/{os.path.basename(control['id'])}",
        'Platform': "",
    }
    checklist_row['Control / MASTG Test'] = control['statement']
    checklist_row['L1'] = ""
    checklist_row['L2'] = ""
    checklist_row['R'] = ""
    checklist.append(checklist_row)

def add_test_rows(checklist, platform, control):
    if platform not in control['tests']:
        return
    for test in control['tests'][platform]:
        levels = test['masvs_v1_levels']
        checklist_row = {
            'MASVS-ID': "",
            'path': f"/MASTG/{os.path.splitext(test['path'])[0]}",
            'Platform': test['platform'],
            'Control / MASTG Test': test['title'],
            'L1': "L1" in levels,
            'L2': "L2" in levels,
            'R': "R" in levels,
        }
        checklist.append(checklist_row)

def get_checklist_dict():
    masvs_v2 = retrieve_masvs()

    mastg_tests = get_tests_dict.get_mastg_tests_dict()

    checklist_dict = {}

    for group in masvs_v2['groups']:

        checklist_per_group = []

        for control in group['controls']:
            add_control_row(checklist_per_group, control)
            control_id = control['id']
            if control_id in mastg_tests:
                control['tests'] = mastg_tests[control_id]
                add_test_rows(checklist_per_group, "android", control)
                add_test_rows(checklist_per_group, "ios", control)

        checklist_dict[group['id']] = checklist_per_group
    return checklist_dict
