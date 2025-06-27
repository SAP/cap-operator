package handler

import (
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
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

func compareDN(x509Name pkix.Name, cred JsonDN) bool {
	// JsonDN slices are already sorted during Unmarshalling
	// We only need to sort the certificate DN slices here
	return check(cred.C, sortSlice(x509Name.Country)) &&
		check(cred.O, sortSlice(x509Name.Organization)) &&
		check(cred.OU, sortSlice(x509Name.OrganizationalUnit)) &&
		check(cred.L, sortSlice(x509Name.Locality)) &&
		cred.CN == x509Name.CommonName
}
