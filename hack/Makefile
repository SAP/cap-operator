# Set shell to bash
SHELL = /usr/bin/env bash
.SHELLFLAGS = -o pipefail -ec
SRC = ./..
PKG = pkg/apis
TEMPDIR=tmp

.PHONY: all
all: build

##@ General

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: manifests
manifests: controller-gen ## Generate CustomResourceDefinition objects.
	$(CONTROLLER_GEN) crd:maxDescLen=0 paths="$(SRC)/$(PKG)/..." output:crd:artifacts:config="$(SRC)/crds"

.PHONY: types
types: ## Generate Types.
	. ./generate.sh

.PHONY: gen-api-docs
gen-api-docs: gen-crd-api-reference-docs ## Generate API docu.
	$(API_DOCS) -config api-reference/config.json -template-dir api-reference/template -api-dir $(SRC)/$(PKG)/sme.sap.com/v1alpha1 -out-file $(SRC)/website/includes/api-reference.html

.PHONY: gen-helm-docs
gen-helm-docs: helm-docs ## Generate helm doc.
	rm -rf $(SRC)/$(TEMPDIR)
	trap 'rm -rf $(SRC)/$(TEMPDIR)' EXIT
	mkdir -p $(SRC)/$(TEMPDIR)
	cp -pr $(SRC)/../cap-operator-lifecycle/chart $(SRC)/$(TEMPDIR)

	$(HELM_DOCS) -c $(SRC)/$(TEMPDIR)/chart -s file
	cp $(SRC)/$(TEMPDIR)/chart/README.md $(SRC)/../cap-operator-lifecycle/chart

	echo '{{ template "chart.valuesSection" . }}' >$(SRC)/$(TEMPDIR)/chart/README.md.gotmpl
	$(HELM_DOCS) -c $(SRC)/$(TEMPDIR) -s file
	cp $(SRC)/$(TEMPDIR)/chart/README.md $(SRC)/website/includes/chart-values.md
	rm -rf $(SRC)/$(TEMPDIR)

##@ Build Dependencies

## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)

## Tool Binaries
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen

## Tool Versions
CONTROLLER_TOOLS_VERSION ?= v0.13.0

.PHONY: controller-gen
controller-gen: $(CONTROLLER_GEN) ## Download controller-gen locally if necessary.
$(CONTROLLER_GEN): $(LOCALBIN)
	test -s $(LOCALBIN)/controller-gen || GOBIN=$(LOCALBIN) go install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_TOOLS_VERSION)

API_DOCS ?= $(LOCALBIN)/gen-crd-api-reference-docs

.PHONY: gen-crd-api-reference-docs
gen-crd-api-reference-docs: $(API_DOCS) ## Download gen-crd-api-reference-docs locally if necessary.
$(API_DOCS): $(LOCALBIN)
	test -s $(LOCALBIN)/gen-crd-api-reference-docs || GOBIN=$(LOCALBIN) go install github.com/ahmetb/gen-crd-api-reference-docs@latest

HELM_DOCS ?= $(LOCALBIN)/helm-docs

.PHONY: helm-docs
helm-docs: $(HELM_DOCS) ## Download helm-docs locally if necessary.
$(HELM_DOCS): $(LOCALBIN)
	test -s $(LOCALBIN)/helm-docs || GOBIN=$(LOCALBIN) go install github.com/norwoodj/helm-docs/cmd/helm-docs@latest