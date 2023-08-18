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

cd $(dirname "${BASH_SOURCE[0]}")/..

if [ ! -f go.mod ]; then
  echo "Error: this is not a go module, is it?"
  exit 1
fi

if [ -z "${CODEGEN_PKG:-}" ]; then
  if [ -d ./vendor/k8s.io/code-generator ]; then
    CODEGEN_PKG=./vendor/k8s.io/code-generator
  else
    CODEGEN_PKG=$(go mod download -json k8s.io/code-generator | jq -r '.Dir //empty')
  fi
fi

if [ -z "${GEN_PKG_PATH:-}" ]; then
  GEN_PKG_PATH=$(go list -m)/pkg
fi

echo "PWD: ${PWD}"
echo "CODEGEN_PKG: ${CODEGEN_PKG}"
echo "GEN_PKG_PATH: ${GEN_PKG_PATH}"

rm -rf "${PWD}"/tmp
mkdir -p "${PWD}"/tmp/"${GEN_PKG_PATH}"

ln -s "${PWD}"/pkg/apis "${PWD}"/tmp/"${GEN_PKG_PATH}"/apis

source "${CODEGEN_PKG}/kube_codegen.sh"

kube::codegen::gen_helpers \
  --input-pkg-root "${GEN_PKG_PATH}"/apis \
  --output-base "${PWD}"/tmp \
  --boilerplate ./hack/LICENSE_BOILERPLATE.txt

kube::codegen::gen_client \
  --with-watch \
  --with-applyconfig \
  --input-pkg-root "${GEN_PKG_PATH}"/apis \
  --output-pkg-root "${GEN_PKG_PATH}"/client \
  --output-base "${PWD}"/tmp \
  --boilerplate ./hack/LICENSE_BOILERPLATE.txt

echo "Moving generated code from ${PWD}/tmp/${GEN_PKG_PATH}/client to ${PWD}/pkg"
rm -rf "${PWD}"/pkg/client
mv "${PWD}"/tmp/"${GEN_PKG_PATH}"/client "${PWD}"/pkg

echo "Done.. removing local /tmp dir"
rm -rf "${PWD}"/tmp