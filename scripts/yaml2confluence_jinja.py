#!/usr/bin/env python3
from IPython.core.debugger import Tracer; bp = Tracer()
from jinja2 import Environment, FileSystemLoader
import os
import sys
import re
import requests
from requests.auth import HTTPBasicAuth
import json
from utils import read_yaml_file, push_to_confluence, get_page_id, main_dn_calculatoin_func, map_sigma_logsource_fields_to_real_world_names, calculate_dn_for_dr
import subprocess
import getpass


def read_rule_file(path):
    """Open the file and load it to the variable. Return text"""

    with open(path) as f:
        rule_text = f.read()
        #rule_text = f.read().replace('\n', '')

    return rule_text

ta_mapping = {
  "attack.initial_access": ("Initial Access","TA0001"),
  "attack.execution": ("Execution","TA0002"),
  "attack.persistence": ("Persistence","TA0003"),
  "attack.privilege_escalation": ("Privilege Escalation","TA0004"),
  "attack.defense_evasion": ("Defense Evasion","TA0005"),
  "attack.credential_access": ("Credential Access","TA0006"),
  "attack.discovery": ("Discovery","TA0007"),
  "attack.lateral_movement": ("Lateral Movement","TA0008"),
  "attack.collection": ("Collection","TA0009"),
  "attack.exfiltration": ("Exfiltration","TA0010"),
  "attack.command_and_control": ("Command and Control","TA0011"),
}

def yaml2confluence_jinja(file, type, url, mail, password):

    try:
      import config  # where we define confluence space name, list of DR and TG folders
      space = config.confluence_space_name
      list_of_detection_rules_directories = config.list_of_detection_rules_directories # not used so far
      list_of_triggering_directories = config.list_of_triggering_directories           # not used so far
      confluence_name_of_root_directory = config.confluence_name_of_root_directory        # not used so far
    except:
      space = "SOC"
      pass

    auth = HTTPBasicAuth(mail, password)
    
    # there is a problem with working directory, for now this script must be run from scripts directory
    env = Environment(loader=FileSystemLoader('templates'))
    fields = read_yaml_file(file)
    
    if type=="detectionrule" or type=="DR":
      alert = fields
      template = env.get_template('confluence_alert_template.html.j2')
      parent_title="Detection Rules"

      sigma_rule = read_rule_file(file)
      alert.update({'sigma_rule':sigma_rule})

      outputs = ["es-qs", "xpack-watcher", "graylog"]

      for output in outputs:
        cmd = "../detectionrules/sigma/tools/sigmac -t "+output+" --ignore-backend-errors "+file
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        (query, err) = p.communicate()
        ## Wait for date to terminate. Get return returncode ##
        p_status = p.wait()
        ## have to remove '-' due to problems with Jinja2 variable naming,e.g es-qs throws error 'no es variable'
        alert.update({output.replace("-", ""):str(query)[2:-3]})

      ###Data Needed
      data_needed = main_dn_calculatoin_func(file)
      data_needed_with_id = []

      for data in data_needed:
        data_needed_id = str(get_page_id(url, auth, space, data))
        data = (data, data_needed_id)
        data_needed_with_id.append(data)

      alert.update({'data_needed':data_needed_with_id})

      tactic = []
      tactic_re = re.compile(r'attack\.\w\D+$')
      technique = []
      technique_re = re.compile(r'attack\.t\d{1,5}$')
      other_tags = []

      for tag in alert.get('tags'):
        if tactic_re.match(tag):
          tactic.append(ta_mapping.get(tag))
        elif technique_re.match(tag):
          technique.append(tag.upper()[7:])
        else:
          other_tags.append(tag)

      alert.update({'tactics':tactic})
      alert.update({'techniques':technique})
      alert.update({'other_tags':other_tags})
      triggers = []

      for trigger in technique:
        #trigger = re.search('t\d{1,5}', trigger).group(0).upper()
        path = '../triggering/atomic-red-team/atomics/'+trigger+'/'+trigger+'.yaml'
        
        try:
          trigger_yaml = read_yaml_file(path)
          #main(path,'triggering')

          trigger_id = str(get_page_id(url, auth, space, trigger))

          trigger = ( trigger, trigger_id )
          print(trigger)

          triggers.append(trigger)
        except FileNotFoundError:
          print(trigger+": No atomics trigger for this technique")

      alert.update({'triggers':triggers})
      content = template.render(alert)

    elif type=="loggingpolicy" or type=="LP":
      template = env.get_template('confluence_loggingpolicy_template.html.j2')
      parent_title="Logging Policies"
      
      content = template.render(fields)

    elif type=="dataneeded" or type=="DN":
      template = env.get_template('confluence_dataneeded_template.html.j2')
      parent_title="Data Needed"
      logging_policies = fields.get("loggingpolicy")

      logging_policies_with_id = [] 

      for lp in logging_policies:
        logging_policies_id = str(get_page_id(url, auth, space, lp))
        lp = (lp, logging_policies_id)
        logging_policies_with_id.append(lp)

      fields.update({'loggingpolicy':logging_policies_with_id})
      content = template.render(fields)

    elif type=="responseaction" or type=="RA":
      template = env.get_template('confluence_responseaction_template.md.j2')
      parent_title="Response Actions"
      linked_ra = fields.get("linked_ra")

      if linked_ra:
        linked_ra_with_id = []
        for ra in linked_ra:
          linked_ra_id = str(get_page_id(url, auth, space, ra))
          ra = (ra, linked_ra_id)
          linked_ra_with_id.append(ra)

        fields.update({'linkedra':linked_ra_with_id})

      fields.update({'description':fields.get('description').strip()}) 
      content = template.render(fields)

    elif type=="responseplaybook" or type=="RP":
      template = env.get_template('confluence_responseplaybook_template.md.j2')
      parent_title="Response Playbooks"

      tactic = []
      tactic_re = re.compile(r'attack\.\w\D+$')
      technique = []
      technique_re = re.compile(r'attack\.t\d{1,5}$')
      other_tags = []

      for tag in fields.get('tags'):
        if tactic_re.match(tag):
          tactic.append(ta_mapping.get(tag))
        elif technique_re.match(tag):
          technique.append(tag.upper()[7:])
        else:
          other_tags.append(tag)

      fields.update({'tactics':tactic})
      fields.update({'techniques':technique})
      fields.update({'other_tags':other_tags})

      # get links to response action

      identification = []
      containment = []
      eradication = []
      recovery = []
      lessons_learned = []

      stages = [('identification', identification), ('containment', containment), 
                ('eradication', eradication), ('recovery', recovery), 
                ('lessons_learned', lessons_learned)]

      for stage_name, stage_list in stages:
        try:
          for task in fields.get(stage_name):
            action = read_yaml_file('../response_actions/'+task+'.yml')
            action_title = action.get('title')
            stage_list.append( (action_title, str(get_page_id(url, auth, space, action_title))) )
        except TypeError:
          pass

      # change stages name to more pretty format
      stages = [ (stage_name.replace('_',' ').capitalize(), stage_list) for stage_name, stage_list in stages ]

      fields.update({'stages_with_id': stages})

      # get descriptions for response actions

      identification = []
      containment = []
      eradication = []
      recovery = []
      lessons_learned = []

      stages = [('identification', identification), ('containment', containment), 
                ('eradication', eradication), ('recovery', recovery), 
                ('lessons_learned', lessons_learned)]

      # grab workflow per action in each IR stages, error handling for playbooks with empty stages
      for stage_name, stage_list in stages:
        try:
          for task in fields.get(stage_name):
            action = read_yaml_file('../response_actions/'+task+'.yml')
            stage_list.append( (action.get('description'), action.get('workflow')) )
        except TypeError:
          pass

      # change stages name to more pretty format
      stages = [ (stage_name.replace('_',' ').capitalize(), stage_list) for stage_name, stage_list in stages ]
      
      fields.update({'stages': stages})

      fields.update({'description':fields.get('description').strip()}) 
      content = template.render(fields)

    elif type=="triggering" or type=="TG":
      template = env.get_template('confluence_trigger_template.html.j2')
      parent_title="Triggering"

      atomic_trigger = read_rule_file(file)

      base = os.path.basename(file)
      trigger = os.path.splitext(base)[0]
      path_md = '../triggering/atomic-red-team/atomics/'+trigger+'/'+trigger+'.md'

      with open(path_md, 'r') as myfile:
        md_data=myfile.read()

      fields.update({'atomic_trigger':atomic_trigger})
      fields.update({'atomic_trigger_md':md_data})
      content = template.render(fields)

    else:
      print("Unsuporrted type")
      return

    base = os.path.basename(file)
    title = os.path.splitext(base)[0]

    data = {
        "title": title,
        "spacekey": space,
        "parentid": str(get_page_id(url, auth, space, parent_title)),
        "confluencecontent": content,
    }
    
    # for debbugging purpouses
    # with open("confluence_from_template.html", "w+") as fh:
    #   fh.write(content)
    
    #print(push_to_confluence(data, url, auth))

    push_to_confluence(data, url, auth)
    print("done: "+base)

if __name__ == "__main__":
    mail = input("Mail: ")
    url = input("Rest API Url: ")
    password = getpass.getpass(prompt='Password: ', stream=None)
    yaml2confluence_jinja(sys.argv[1], sys.argv[2], url, mail, password)

