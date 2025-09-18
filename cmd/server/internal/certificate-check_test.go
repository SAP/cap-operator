package handler

import (
	"crypto/x509/pkix"
	"encoding/json"
	"testing"
)

func TestFlexibleOU_UnmarshalJSON_SingleString(t *testing.T) {
	var ou FlexibleOU
	data := []byte(`"Engineering"`)
	err := json.Unmarshal(data, &ou)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ou) != 1 || ou[0] != "Engineering" {
		t.Errorf("expected [Engineering], got %v", ou)
	}
}

func TestFlexibleOU_UnmarshalJSON_StringSlice(t *testing.T) {
	var ou FlexibleOU
	data := []byte(`["Engineering", "QA"]`)
	err := json.Unmarshal(data, &ou)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ou) != 2 || ou[0] != "Engineering" || ou[1] != "QA" {
		t.Errorf("expected [Engineering QA], got %v", ou)
	}
}

func TestFlexibleOU_UnmarshalJSON_Invalid(t *testing.T) {
	var ou FlexibleOU
	data := []byte(`123`)
	err := json.Unmarshal(data, &ou)
	if err == nil {
		t.Error("expected error for invalid input, got nil")
	}
}

func TestSortStrings(t *testing.T) {
	input := []string{"b", "a", "c"}
	expected := FlexibleOU{"a", "b", "c"}
	result := sortStrings(input)
	for i := range expected {
		if result[i] != expected[i] {
			t.Errorf("expected %v, got %v", expected, result)
		}
	}
}

func TestFirstOrEmpty(t *testing.T) {
	if firstOrEmpty([]string{"foo", "bar"}) != "foo" {
		t.Error("expected 'foo'")
	}
	if firstOrEmpty([]string{}) != "" {
		t.Error("expected empty string")
	}
}

func TestNormalizeX509(t *testing.T) {
	name := pkix.Name{
		Country:            []string{"DE"},
		Organization:       []string{"SAP"},
		OrganizationalUnit: []string{"A", "B"},
		Locality:           []string{"Walldorf"},
		CommonName:         "test.sap.com",
	}
	ndn := normalizeX509(name)
	if ndn.C != "DE" || ndn.O != "SAP" || ndn.L != "Walldorf" || ndn.CN != "test.sap.com" {
		t.Errorf("unexpected JsonDN: %+v", ndn)
	}
	if len(ndn.OU) != 2 || ndn.OU[0] != "A" || ndn.OU[1] != "B" {
		t.Errorf("unexpected OU: %v", ndn.OU)
	}
}

func TestNormalizeDNJson(t *testing.T) {
	jsonDN := JsonDN{
		C:  "US",
		O:  "Acme",
		OU: FlexibleOU{"Dev", "Ops"},
		L:  "NY",
		CN: "acme.com",
	}
	ndn := normalizeDNJson(jsonDN)
	if ndn.C != "US" || ndn.O != "Acme" || ndn.L != "NY" || ndn.CN != "acme.com" {
		t.Errorf("unexpected JsonDN: %+v", ndn)
	}
	if len(ndn.OU) != 2 || ndn.OU[0] != "Dev" || ndn.OU[1] != "Ops" {
		t.Errorf("unexpected OU: %v", ndn.OU)
	}
}

func TestCompareDN_ExactMatch(t *testing.T) {
	dn1 := JsonDN{C: "DE", O: "SAP", OU: FlexibleOU{"A"}, L: "Walldorf", CN: "test"}
	dn2 := JsonDN{C: "DE", O: "SAP", OU: FlexibleOU{"A"}, L: "Walldorf", CN: "test"}
	if !compareDN(dn1, dn2) {
		t.Error("expected match")
	}
}

func TestCompareDN_WildcardLocality(t *testing.T) {
	dn1 := JsonDN{C: "DE", O: "SAP", OU: FlexibleOU{"A"}, L: "Walldorf", CN: "test"}
	dn2 := JsonDN{C: "DE", O: "SAP", OU: FlexibleOU{"A"}, L: "*", CN: "test"}
	if !compareDN(dn1, dn2) {
		t.Error("expected match with wildcard locality")
	}
}

func TestCompareDN_DifferentOU(t *testing.T) {
	dn1 := JsonDN{C: "DE", O: "SAP", OU: FlexibleOU{"A"}, L: "Walldorf", CN: "test"}
	dn2 := JsonDN{C: "DE", O: "SAP", OU: FlexibleOU{"B"}, L: "Walldorf", CN: "test"}
	if compareDN(dn1, dn2) {
		t.Error("expected mismatch due to OU")
	}
}

func TestCompareDN_DifferentCN(t *testing.T) {
	dn1 := JsonDN{C: "DE", O: "SAP", OU: FlexibleOU{"A"}, L: "Walldorf", CN: "test1"}
	dn2 := JsonDN{C: "DE", O: "SAP", OU: FlexibleOU{"A"}, L: "Walldorf", CN: "test2"}
	if compareDN(dn1, dn2) {
		t.Error("expected mismatch due to CN")
	}
}
