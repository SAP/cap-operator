#!/bin/bash

set -eo pipefail

# Change dir to the root dir of this repo (should point to cap-operator)
cd $(dirname "${BASH_SOURCE[0]}")/../..

echo "PWD: ${PWD}"

TEMPDIR=$(mktemp -d)
trap 'rm -rf "$TEMPDIR"' EXIT

cp -r "$PWD"/../cap-operator-lifecycle/chart "$TEMPDIR"

helm-docs -c "$TEMPDIR"/chart -s file
cp "$TEMPDIR"/chart/README.md "$PWD"/../cap-operator-lifecycle/chart

cat > "$TEMPDIR"/chart/README.md.gotmpl <<END
{{ template "chart.valuesSection" . }}
END
helm-docs -c "$TEMPDIR"/chart -s file
cp "$TEMPDIR"/chart/README.md "$PWD"/website/includes/chart-values.md