### Generate CSR and auth.service.local.key
```
openssl req -newkey rsa:2048 -nodes -sha256 -keyout auth.service.local.key -out csr.cer -subj "/C=DE/ST=RandomState/L=RandomCity/O=RandomOrg/OU=RandomOrgUnit/CN=*.auth.service.local/emailAddress=hello@example.com"
```

### Generate Root CA
```
openssl x509 -req -sha256 -days 3650 -in csr.cer -signkey auth.service.local.key -out rootCA.pem

```

### Generate auth.service.local cert

Create extensions.cfg with:
basicConstraints=CA:FALSE
authorityKeyIdentifier=keyid,issuer
keyUsage=Digital Signature, Non Repudiation, Key Encipherment, Data Encipherment
subjectAltName=DNS:auth.service.local, DNS:*.auth.service.local, IP:127.0.0.1

then execute:

```
openssl x509 -req -sha256 -days 3650 -in csr.cer -CA rootCA.pem -CAkey auth.service.local.key -out auth.service.local.crt  -CAcreateserial -extfile=extensions.cfg -copy_extensions=copyall
```