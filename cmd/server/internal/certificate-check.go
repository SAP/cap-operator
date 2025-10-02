package handler

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"slices"
)

type stringslice []string

func (s *stringslice) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*s = []string{single}
		return nil
	}

	var multiple []string
	if err := json.Unmarshal(data, &multiple); err == nil {
		slices.Sort(multiple)
		*s = multiple
		return nil
	}

	return fmt.Errorf("invalid format")
}

type JsonDN struct {
	C  stringslice `json:"C"`
	O  stringslice `json:"O"`
	OU stringslice `json:"OU"`
	L  stringslice `json:"L"`
	CN string      `json:"CN"`
}

func check(source []string, target []string) bool {
	return slices.Contains(source, "*") || slices.Equal(source, target)
}

func sortSlice(orgSlice []string) []string {
	clone := slices.Clone(orgSlice)
	slices.Sort(clone)
	return clone
}

func compareDN(x509Name pkix.Name, credStringDN string) (ok bool, err error) {
	// convert credential subject or issuer string to JsonDN
	var credDN JsonDN
	err = json.Unmarshal([]byte(credStringDN), &credDN)
	if err == nil {
		// JsonDN slices are already sorted during Unmarshalling
		// We only need to sort the certificate pkix.Name attribute slices here
		ok = check(credDN.C, sortSlice(x509Name.Country)) &&
			check(credDN.O, sortSlice(x509Name.Organization)) &&
			check(credDN.OU, sortSlice(x509Name.OrganizationalUnit)) &&
			check(credDN.L, sortSlice(x509Name.Locality)) &&
			credDN.CN == x509Name.CommonName
	}
	return ok, err
}

func checkCertificate(xForwardedClientCert, certificateIssuer, certificateSubject string) error {
	if xForwardedClientCert == "" {
		return errors.New("x-forwarded-client-cert header is empty")
	}

	// Decode PEM block
	decodedValue, err := url.QueryUnescape(xForwardedClientCert)
	if err != nil {
		return err
	}

	block, _ := pem.Decode([]byte(decodedValue))
	if block == nil {
		return errors.New("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}

	if ok, err := compareDN(cert.Issuer, certificateIssuer); err != nil || !ok {
		return fmt.Errorf("certificate issuer mismatch, original error: %w", err)
	}

	if ok, err := compareDN(cert.Subject, certificateSubject); err != nil || !ok {
		return fmt.Errorf("certificate subject mismatch, original error: %w", err)
	}

	return nil
}
