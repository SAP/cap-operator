/*
SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package handler

import (
	"net/http"
)

type httpClientGenerator interface {
	NewHTTPClient() *http.Client
}

type httpClientGeneratorImpl struct{}

func (facade *httpClientGeneratorImpl) NewHTTPClient() *http.Client {
	return &http.Client{}
}
