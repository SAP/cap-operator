#!/bin/bash

set -eo pipefail

# Change directory to the script dir (i.e. .../hack/api-reference/)
cd $(dirname "${BASH_SOURCE[0]}")

echo "PWD: ${PWD}"

gen-crd-api-reference-docs \
  -config config.json \
  -template-dir template \
  -api-dir ../../pkg/apis/sme.sap.com/v1alpha1 \
  -out-file ../../website/includes/api-reference.html
