#!/bin/bash

DIRECTORIES=(
  "../Atomic_Threat_Coverage"
  "../Atomic_Threat_Coverage/Detection_Rules"
  "../Atomic_Threat_Coverage/Logging_Policies"
  "../Atomic_Threat_Coverage/Data_Needed"
  "../Atomic_Threat_Coverage/Triggers"
  "../Atomic_Threat_Coverage/Response_Actions"
  "../Atomic_Threat_Coverage/Response_Playbooks"
  "../Atomic_Threat_Coverage/Enrichments"

)

for DIRECTORY in ${DIRECTORIES[@]}; do
  if [[ ! -d ${DIRECTORY} ]]; then
    mkdir ${DIRECTORY}
  fi
done
