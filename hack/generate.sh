#!/bin/bash

set -o errexit
set -o nounset
set -o pipefail

if ! which go >/dev/null; then
  echo "Error: go not found in path"
  exit 1
fi

if ! which jq >/dev/null; then
  echo "Error: jq not found in path"
  exit 1
fi

mkdir -p ./tmp/go

if [ ! -f ./tmp/go.mod ]; then
  cd ./tmp
  echo "Creating Temporary go.mod file"
  go mod init sap.com/test
  cd ..
fi

echo $(go get -modfile=./tmp/go.mod k8s.io/code-generator@latest)
CODEGEN_PKG=$(go list -modfile=./tmp/go.mod -m -f {{.Dir}} k8s.io/code-generator)

cd $(dirname "${BASH_SOURCE[0]}")/..

if [ -z "${GEN_PKG_PATH:-}" ]; then
  GEN_PKG_PATH=$(go list -m)/pkg
fi

echo "PWD: ${PWD}"
echo "CODEGEN_PKG: ${CODEGEN_PKG}"
echo "GEN_PKG_PATH: ${GEN_PKG_PATH}"

source "${CODEGEN_PKG}/kube_codegen.sh"

kube::codegen::gen_helpers \
  --boilerplate ./hack/LICENSE_BOILERPLATE.txt \
  ./pkg/apis

kube::codegen::gen_client \
  --with-watch \
  --with-applyconfig \
  --output-dir "./pkg/client" \
  --output-pkg "${GEN_PKG_PATH}"/client \
  --boilerplate ./hack/LICENSE_BOILERPLATE.txt \
  ./pkg/apis