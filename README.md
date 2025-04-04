# [CAP Operator](https://sap.github.io/cap-operator/)
[![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/SAP/cap-operator)](https://github.com/SAP/cap-operator/blob/main/go.mod#L3)
[![Go Reference](https://pkg.go.dev/badge/github.com/sap/cap-operator.svg)](https://pkg.go.dev/github.com/sap/cap-operator)
[![Go Report Card](https://goreportcard.com/badge/github.com/sap/cap-operator)](https://goreportcard.com/report/github.com/sap/cap-operator)
[![Sonar Coverage](https://sonarcloud.io/api/project_badges/measure?project=SAP_cap-operator&metric=coverage)](https://sonarcloud.io/summary/overall?id=SAP_cap-operator)
[![CodeQL](https://github.com/SAP/cap-operator/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/SAP/cap-operator/actions/workflows/github-code-scanning/codeql)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/7803/badge)](https://www.bestpractices.dev/projects/7803)
[![REUSE status](https://api.reuse.software/badge/github.com/SAP/cap-operator)](https://api.reuse.software/info/github.com/SAP/cap-operator)

CAP Operator manages the lifecycle operations involved in running multi-tenant CAP applications on Kubernetes clusters, primarily project "Gardener" managed clusters.

#### Documentation
Visit the [Documentation](https://sap.github.io/cap-operator/docs) to find out how to install and use the CAP Operator

#### Setup
The operator can be deployed using the [helm chart](https://github.com/sap/cap-operator-lifecycle/tree/main/chart) which is part of [CAP Operator Lifecycle](https://github.com/sap/cap-operator-lifecycle) repo.

#### CRDs
CRDs for the CAP Operator can be applied from the [./crds](./crds) folder, these are also copied over to the [helm chart](https://github.com/sap/cap-operator-lifecycle/tree/main/chart) when released.


## Support, Feedback, Contributing

This project is open to feature requests/suggestions, bug reports etc. via [GitHub issues](https://github.com/SAP/cap-operator/issues). Contribution and feedback are encouraged and always welcome. For more information about how to contribute, the project structure, as well as additional contribution information, see our [Contribution Guidelines](CONTRIBUTING.md).

## Code of Conduct

We as members, contributors, and leaders pledge to make participation in our community a harassment-free experience for everyone. By participating in this project, you agree to abide by its [Code of Conduct](https://github.com/SAP/.github/blob/main/CODE_OF_CONDUCT.md) at all times.

## Licensing

Copyright 2025 SAP SE or an SAP affiliate company and cap-operator contributors. Please see our [LICENSE](LICENSE) for copyright and license information. Detailed information including third-party components and their licensing/copyright information is available [via the REUSE tool](https://api.reuse.software/info/github.com/SAP/cap-operator).
