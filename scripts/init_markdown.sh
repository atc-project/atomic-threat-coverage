#!/bin/bash

OUTPUT_PATH=`grep md_name_of_root_directory config.yml | sed -e "s/^.*\'\(.*\)\'.*$/\1/"`

if [ -z "$OUTPUT_PATH" ]; then
  OUTPUT_PATH="../Atomic_Threat_Coverage"
fi

DIRECTORIES=(
  "$OUTPUT_PATH"
  "$OUTPUT_PATH/Detection_Rules"
  "$OUTPUT_PATH/Logging_Policies"
  "$OUTPUT_PATH/Data_Needed"
  "$OUTPUT_PATH/Triggers"
  "$OUTPUT_PATH/Response_Actions"
  "$OUTPUT_PATH/Response_Playbooks"
  "$OUTPUT_PATH/Enrichments"
)

for DIRECTORY in ${DIRECTORIES[@]}; do
  if [[ ! -d ${DIRECTORY} ]]; then
    mkdir ${DIRECTORY}
  fi
done

