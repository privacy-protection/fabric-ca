package cpabe

import (
	"encoding/asn1"
)

var (
	// ParamsOID is the ASN.1 object identifier for an cpabe params extension in an X509 certificate
	ParamsOID = asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 7, 8, 9}
	// ParamsOIDString is the string version of ParamsOID
	ParamsOIDString = "1.2.3.4.5.6.7.8.9"
)
