#!/bin/bash

for FILE in $( find sigma/rules -name "*.yml" ); do
  FILENAME=$( basename ${FILE} | cut -f 1 -d '.' )
  python3 sigma/tools/sigmac -t es-qs --ignore-backend-errors -o rules-md/${FILENAME}-es-qs.md ${FILE}
  python3 sigma/tools/sigmac -t graylog --ignore-backend-errors -o rules-md/${FILENAME}-graylog.md ${FILE}
done