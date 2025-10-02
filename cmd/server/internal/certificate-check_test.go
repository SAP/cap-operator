package handler

import (
	"crypto/x509/pkix"
	"net/url"
	"strings"
	"testing"
)

var xfccHeader = url.QueryEscape("-----BEGIN CERTIFICATE-----\nMIID0zCCArsCFGW07a83z8cK1c0JIkHXX+h4CO6IMA0GCSqGSIb3DQEBCwUAMIGl\nMQswCQYDVQQGEwJERTEUMBIGA1UECAwLUmFuZG9tU3RhdGUxEzARBgNVBAcMClJh\nbmRvbUNpdHkxEjAQBgNVBAoMCVJhbmRvbU9yZzEWMBQGA1UECwwNUmFuZG9tT3Jn\nVW5pdDEdMBsGA1UEAwwUKi5hdXRoLnNlcnZpY2UubG9jYWwxIDAeBgkqhkiG9w0B\nCQEWEWhlbGxvQGV4YW1wbGUuY29tMB4XDTIzMDkyMTIzNDQ0NVoXDTMzMDkxODIz\nNDQ0NVowgaUxCzAJBgNVBAYTAkRFMRQwEgYDVQQIDAtSYW5kb21TdGF0ZTETMBEG\nA1UEBwwKUmFuZG9tQ2l0eTESMBAGA1UECgwJUmFuZG9tT3JnMRYwFAYDVQQLDA1S\nYW5kb21PcmdVbml0MR0wGwYDVQQDDBQqLmF1dGguc2VydmljZS5sb2NhbDEgMB4G\nCSqGSIb3DQEJARYRaGVsbG9AZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUA\nA4IBDwAwggEKAoIBAQDgkMvORiISYn26ysvrtFZ5nK19vMzdDI0+qC6eiO02ImNE\nroMZ39fXPX0rryU3iNOqjgNe6Dx2pbmgTLrqPeHmWuxHVo+jOCV7G7LbDJCS43an\nb/emfEYMOL76YLg0/ZQo1HePrxF2Exnxmv5erpmD39WYj6pxVZjcM8QbWrBU1eMI\nyuEW5pudv+T55Zw3CUHwbKQ/fwgGwF9rVX4WmUlgXvwcQqHshtloHJLbWqjoS/tp\nek1Wfk3iaUKHnCz4TMH/6urrU68zVoF43CxIfs0mdENdP2gJM3SgIX15bySxqPIc\nEUle0Hg7Cd4FaOCDzCZSoK4K6fE1NYAuWolNVDphAgMBAAEwDQYJKoZIhvcNAQEL\nBQADggEBAN91XXjgLUgJEIhisdtyV9yEf53vr4ddQ3n1J3XJkToPbh46R2lXez4S\n38na3IM9UPAWGiqq7xDxhi2ieu8H4ww6akBvOCm5vs4PhXWCkuzzF2BLaBoT8hsk\nVRbylzZbzshicPMLoMRi7sVKoc6mD80Nta2BMFNClLE01ow/wFx3HH4rWviaiNHd\ngJ/gvffN70p24BEoP4LRbXQKUSeCjRdWvw9QdpDIYyqRPLSWuupB5JmO5dPx9IXF\n59Fro6wA9NRIzcXD+Ig8U3AbxHMtQemdcofjTGW+3V9Ozs/YQGuqdotQ020V9mR5\n59Xddx06ziMyA9DY4mnO3+5gVN2haKw=\n-----END CERTIFICATE-----")

const (
	validIssuer  = "{\"C\":\"DE\",\"L\":\"*\",\"O\":\"RandomOrg\",\"OU\":\"RandomOrgUnit\",\"CN\":\"*.auth.service.local\"}"
	validSubject = "{\"CN\":\"*.auth.service.local\",\"L\":\"RandomCity\",\"OU\": [\"RandomOrgUnit\"],\"O\":\"RandomOrg\",\"C\":\"DE\"}"
)

func TestCheckCertificateHeader_Empty(t *testing.T) {
	err := checkCertificate("", validIssuer, validSubject)
	if err == nil {
		t.Error("expected error for empty xfcc header")
	} else if err.Error() != "x-forwarded-client-cert header is empty" {
		t.Errorf("expected 'x-forwarded-client-cert header is empty' error, got: %v", err)
	}
}

func TestCheckCertificateHeader_InvalidEscaping(t *testing.T) {
	invalidChar := strings.Replace(xfccHeader, "W07", "%xy", 1)
	err := checkCertificate(invalidChar, validIssuer, validSubject)
	if err == nil {
		t.Error("expected error for invalid xfcc header")
	} else if err.Error() != "invalid URL escape \"%xy\"" {
		t.Errorf("expected 'invalid URL escape ..' error, got: %v", err)
	}
}

func TestCheckCertificateHeader_InValidPEM(t *testing.T) {
	invalidPEM := url.QueryEscape("-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----")
	err := checkCertificate(invalidPEM, validIssuer, validSubject)
	if err == nil {
		t.Error("expected error for invalid PEM block")
	} else if err.Error() != "failed to decode PEM block" {
		t.Errorf("expected 'failed to decode PEM block' error, got: %v", err)
	}
}

func TestCheckCertificateHeader_InvalidCert(t *testing.T) {
	// Example of a certificate with negative serial number.
	// This will cause an x509 parse error.
	invalidCert := url.QueryEscape(`-----BEGIN CERTIFICATE-----
MIID6DCCAtCgAwIBAgIB/zANBgkqhkiG9w0BAQsFADCBpTELMAkGA1UEBhMCREUx
FDASBgNVBAgMC1JhbmRvbVN0YXRlMRMwEQYDVQQHDApSYW5kb21DaXR5MRIwEAYD
VQQKDAlSYW5kb21PcmcxFjAUBgNVBAsMDVJhbmRvbU9yZ1VuaXQxHTAbBgNVBAMM
FCouYXV0aC5zZXJ2aWNlLmxvY2FsMSAwHgYJKoZIhvcNAQkBFhFoZWxsb0BleGFt
cGxlLmNvbTAeFw0yNTEwMDIxNDI2MTVaFw0zNTA5MzAxNDI2MTVaMIGlMQswCQYD
VQQGEwJERTEUMBIGA1UECAwLUmFuZG9tU3RhdGUxEzARBgNVBAcMClJhbmRvbUNp
dHkxEjAQBgNVBAoMCVJhbmRvbU9yZzEWMBQGA1UECwwNUmFuZG9tT3JnVW5pdDEd
MBsGA1UEAwwUKi5hdXRoLnNlcnZpY2UubG9jYWwxIDAeBgkqhkiG9w0BCQEWEWhl
bGxvQGV4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
mSkvV1AE/yE9azW8UYwXNOkiXYR9Eg8etmMHXxhI5LRCPMOa/FY8vhdXxd98RgNi
ZjtIReNzsLuT/Icm8s1vI89STtfwF8L5qFKXDnoajB31UU17/rGp8gfNYjRWxSZ3
p4NT6XGeWBA5Ho3bDy0WsL3iOe1p6LVzDchaYTP+8FPd++0h4CiZyFsRckigIgFv
eaYPQtHtv2MA9jSbSIm50MUliAOqxfglxjlWk4oKkDSDxerpl94cD4ZIopUjDrEy
nqIw60IoypRK52b7yXOuf7G+OmRDvdgvj5ewnFSvaA6MawfRS8iNGDtSreort6YL
9JlSEZCoGCJeLW4SGQrndQIDAQABoyEwHzAdBgNVHQ4EFgQUiO373cERaGFctQQr
P1oBnx1R/y4wDQYJKoZIhvcNAQELBQADggEBADG8HGFNrap41t8F5giBRLIovDCp
zD/VEvhWFTgJv/wVPKQXaafQJgzhG4FZZSFTNMtMFtZk2IYNsQAvu1ybm4H8HwHm
+YiJpIRaJE5fG+fjcgN4DDrtVZKJb++wKEKsR7kIFgYAbpIfBN3AsbpZbIbWcQE7
WUF+YPPhxpa+BNSuYvBTvLio2QpWmiikXkEHloCVlpt9ajOsXgfabKTxdQc2/0MU
pcxfzkelBJXU7OTHbfBNsckW3FzfO67/s9LovIaTiQuns5l7MgtNxop2oqthziSf
e5q59aBMibj8zZg2UIGXcSnxsDGKZD/PQxgACr+PohH+GiK2WdheRu9VK6I=
-----END CERTIFICATE-----`)

	err := checkCertificate(invalidCert, validIssuer, validSubject)
	if err == nil {
		t.Error("expected error for invalid certificate")
	} else if !strings.Contains(err.Error(), "x509: negative serial number") {
		t.Errorf("expected x509 parse error, got: %v", err)
	}
}

func TestCheckCertificate_IssuerMismatch(t *testing.T) {
	err := checkCertificate(xfccHeader, "issuer", validSubject)
	if err == nil {
		t.Error("expected error for invalid issuer")
	} else if !strings.Contains(err.Error(), "certificate issuer mismatch") {
		t.Errorf("expected 'certificate issuer mismatch' error, got: %v", err)
	}
}

func TestCheckCertificate_SubjectMismatch(t *testing.T) {
	err := checkCertificate(xfccHeader, validIssuer, "subject")
	if err == nil {
		t.Error("expected error for invalid subject")
	} else if !strings.Contains(err.Error(), "certificate subject mismatch") {
		t.Errorf("expected 'certificate subject mismatch' error, got: %v", err)
	}
}

func TestCheckCertificate_Valid(t *testing.T) {
	err := checkCertificate(xfccHeader, validIssuer, validSubject)
	if err != nil {
		t.Error("expected certificate check to pass, got error:", err)
	}
}

func TestCompareDN_InvalidJson(t *testing.T) {
	name := pkix.Name{
		Country:            []string{"DE"},
		Organization:       []string{"SAP"},
		OrganizationalUnit: []string{"A", "B"},
		Locality:           []string{"Walldorf"},
		CommonName:         "test.sap.com",
	}
	jsonString := `{"C":{"invalid":"val"}}`
	ok, err := compareDN(name, jsonString)
	if err == nil && ok {
		t.Error("expected json unmarshal error")
	} else if err.Error() != "invalid format" {
		t.Errorf("expected 'invalid format' error, got: %v", err)
	}
}

func TestCompareDN_ExactMatch(t *testing.T) {
	name := pkix.Name{
		Country:            []string{"DE"},
		Organization:       []string{"SAP"},
		OrganizationalUnit: []string{"A", "B"},
		Locality:           []string{"Walldorf"},
		CommonName:         "test.sap.com",
	}
	jsonString := `{"C":"DE","O":"SAP","OU":["A","B"],"L":"Walldorf","CN":"test.sap.com"}`
	if ok, err := compareDN(name, jsonString); err != nil || !ok {
		t.Error("expected match")
	}
}

func TestCompareDN_WildcardLocality(t *testing.T) {
	name := pkix.Name{
		Country:            []string{"DE"},
		Organization:       []string{"SAP"},
		OrganizationalUnit: []string{"A", "B"},
		Locality:           []string{"Walldorf"},
		CommonName:         "test.sap.com",
	}
	jsonString := `{"C":"DE","O":"SAP","OU":["A","B"],"L":"*","CN":"test.sap.com"}`
	if ok, err := compareDN(name, jsonString); err != nil || !ok {
		t.Error("expected match with wildcard locality")
	}
}

func TestCompareDN_DifferentOU(t *testing.T) {
	name := pkix.Name{
		Country:            []string{"DE"},
		Organization:       []string{"SAP"},
		OrganizationalUnit: []string{"A"},
		Locality:           []string{"Walldorf"},
		CommonName:         "test.sap.com",
	}
	jsonString := `{"C":"DE","O":"SAP","OU":"B","L":"Walldorf","CN":"test.sap.com"}`
	if ok, err := compareDN(name, jsonString); err == nil && ok {
		t.Error("expected mismatch due to OU")
	}
}

func TestCompareDN_DifferentCN(t *testing.T) {
	name := pkix.Name{
		Country:            []string{"DE"},
		Organization:       []string{"SAP"},
		OrganizationalUnit: []string{"A"},
		Locality:           []string{"Walldorf"},
		CommonName:         "test.sap.com",
	}
	jsonString := `{"C":"DE","O":"SAP","OU":"A","L":"Walldorf","CN":"test2.some.org"}`
	if ok, err := compareDN(name, jsonString); err == nil && ok {
		t.Error("expected mismatch due to CN")
	}
}
