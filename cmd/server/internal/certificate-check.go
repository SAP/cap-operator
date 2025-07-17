package handler

import (
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
)

// Minimum exposure, required to compile
type FlexibleOU []string

func (f *FlexibleOU) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*f = []string{single}
		return nil
	}

	var multiple []string
	if err := json.Unmarshal(data, &multiple); err == nil {
		*f = multiple
		return nil
	}

	return fmt.Errorf("invalid OU format")
}

type JsonDN struct {
	C  string     `json:"C"`
	O  string     `json:"O"`
	OU FlexibleOU `json:"OU"`
	L  string     `json:"L"`
	CN string     `json:"CN"`
}

type NormalizedDN struct {
	C  string
	O  string
	OU FlexibleOU
	L  string
	CN string
}

func sortStrings(slice []string) FlexibleOU {
	sorted := make([]string, len(slice))
	copy(sorted, slice)
	sort.Strings(sorted)
	return FlexibleOU(sorted)
}

func firstOrEmpty(slice []string) string {
	if len(slice) > 0 {
		return slice[0]
	}
	return ""
}

// Normalize Go x509 Name
func normalizeX509(name pkix.Name) NormalizedDN {
	return NormalizedDN{
		C:  firstOrEmpty(name.Country),
		O:  firstOrEmpty(name.Organization),
		OU: sortStrings(name.OrganizationalUnit),
		L:  firstOrEmpty(name.Locality),
		CN: name.CommonName,
	}
}

// Normalize JSON DN
func normalizeDNJson(jsonDN JsonDN) NormalizedDN {
	return NormalizedDN{
		C:  jsonDN.C,
		O:  jsonDN.O,
		OU: sortStrings(jsonDN.OU),
		L:  jsonDN.L,
		CN: jsonDN.CN,
	}
}

func compareDN(dn1, dn2 NormalizedDN) bool {
	return dn1.C == dn2.C &&
		dn1.O == dn2.O &&
		reflect.DeepEqual(dn1.OU, dn2.OU) &&
		(dn1.L == dn2.L || dn2.L == "*") && // Wildcard handling
		dn1.CN == dn2.CN
}
