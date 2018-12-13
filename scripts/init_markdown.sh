#!/bin/bash

DIRECTORIES=(
  "Atomic_Threat_Coverage"
  "Atomic_Threat_Coverage/Detection_Rules"
  "Atomic_Threat_Coverage/Logging_Policies"
  "Atomic_Threat_Coverage/Data_Needed"
  "Atomic_Threat_Coverage/Triggering"
)

for DIRECTORY in ${DIRECTORIES[@]}; do
  if [[ ! -d ${DIRECTORY} ]]; then
    mkdir ${DIRECTORY}
  fi
done