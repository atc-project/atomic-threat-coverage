#!/bin/bash

DIRECTORIES=(
  "../Atomic_Threat_Coverage"
  "../Atomic_Threat_Coverage/Detection_Rules"
  "../Atomic_Threat_Coverage/Logging_Policies"
  "../Atomic_Threat_Coverage/Data_Needed"
  "../Atomic_Threat_Coverage/Triggering"
  "../Atomic_Threat_Coverage/Response_Actions"
  "../Atomic_Threat_Coverage/Response_Playbooks"
)

for DIRECTORY in ${DIRECTORIES[@]}; do
  if [[ ! -d ${DIRECTORY} ]]; then
    mkdir ${DIRECTORY}
  fi
done
