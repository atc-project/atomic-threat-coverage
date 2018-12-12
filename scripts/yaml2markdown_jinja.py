#!/usr/bin/env python3

from jinja2 import Environment, FileSystemLoader
import yaml
import os
import sys
import subprocess
import re

from utils import read_yaml_file, main_dn_calculatoin_func, read_rule_file

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

def yaml2markdown_jinja(file, type):

    # there is a problem with working directory, for now this script must be run from scripts directory
    env = Environment(loader=FileSystemLoader('templates'))
    fields = read_yaml_file(file)
    
    if type=="detectionrule" or type=="DR":
      alert = fields
      template = env.get_template('markdown_alert_template.md.j2')
      parent_title="Detection_Rules"

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

      alert.update({'data_needed':data_needed})

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

          triggers.append(trigger)
        except FileNotFoundError:
          print(trigger+": No atomics trigger for this technique")
          triggers.append(trigger+": No atomics trigger for this technique")

      alert.update({'description':alert.get('description').strip()}) 
      alert.update({'triggers':triggers})
      content = template.render(alert)

    elif type=="loggingpolicy" or type=="LP":
      template = env.get_template('markdown_loggingpolicy_template.md.j2')
      parent_title="Logging_Policies"
      
      # get rid of newline to not mess with table in md
      fields.update({'description':fields.get('description').strip()}) 
      content = template.render(fields)

    elif type=="dataneeded" or type=="DN":
      template = env.get_template('markdown_dataneeded_template.md.j2')
      parent_title="Data_Needed"

      fields.update({'description':fields.get('description').strip()}) 
      content = template.render(fields)

    elif type=="triggering" or type=="TG":
      pass

    else:
      print("Unsuporrted type")
      return


    base = os.path.basename(file)
    title = os.path.splitext(base)[0]
    
    with open('../Atomic_Threat_Coverage/'+parent_title+"/"+title+".md", "w+") as fh:
      fh.write(content)


if __name__ == "__main__":
    """sys.argv[1] is the name of the file"""

    yaml2markdown_jinja(sys.argv[1], sys.argv[2])