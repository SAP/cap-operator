package handler

import (
	"crypto/x509/pkix"
	"encoding/json"
	"testing"
)

func TestJsonDN_InvalidJson(t *testing.T) {
	jsonString := `{"C":{"invalid"}}`
	dn := JsonDN{}
	err := json.Unmarshal([]byte(jsonString), &dn)
	if err == nil {
		t.Error("expected error for invalid JSON")
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
	dn := JsonDN{}
	json.Unmarshal([]byte(jsonString), &dn)
	if !compareDN(name, dn) {
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
	dn := JsonDN{}
	json.Unmarshal([]byte(jsonString), &dn)
	if !compareDN(name, dn) {
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
	dn := JsonDN{}
	json.Unmarshal([]byte(jsonString), &dn)
	if compareDN(name, dn) {
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
	dn := JsonDN{}
	json.Unmarshal([]byte(jsonString), &dn)
	if compareDN(name, dn) {
		t.Error("expected mismatch due to CN")
	}
}
