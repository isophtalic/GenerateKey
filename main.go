package main

import (
	"fmt"

	"github.com/isophtalic/GenerateKey/lib/rsa"
	"github.com/isophtalic/GenerateKey/utilities"
)

var info = `XREk/gIQ4ILkiR3jDGIWJULOYS2NZfC9lzQHyvQ6HYJDDoZIeRNVivE19x/Gn7zxWE8uSsHSSJCDzw7KFBX17YQeMNXOeUFQTsyaRbIbeIYl5cUgz3RQLxFwG8OWSAEmsBCmGCIPXLx6j8XQOZ0XTaGVlr+C8ZDiAr+im+eMmz/eCL5Y+EaEzOQVrXoWK+jhIWbfR57AHEVjZ42llORcTQM+Q2nipnrnbgm9Sb5l34uR5HuDSIbB6Sseca0ZyfRdRVUQ3u26bpCiIiPN/BzvIRp7XNSYmw/aUbDBKLxZRMO0zQ65UkRLTk+zcD5Kwy35HHFHuObfRIYnDuiGi5MCIkQlhGUDIunWLHPmQMV0aDwYwqfzM573rtS4cy+X4XVMDMFgO5pLTy1ArncmfzIxINWl7PLAedGNaVN+rcGGPBD0Q+OAtIXJPaA1avOGtyA18POie3aDsn0oJ6rvluNX1bzSBWckV4eysWoX8IyC1Mk=`

func main() {
	var newRSA rsa.RSA
	newRSA.GenerateKey("./keys/pub.pem", "./keys/pri.pem", 2048)
	pubKey, priKey := utilities.LoadKeyFromFile("./keys/pub.pem", "./keys/pri.pem")
	infoSignedString := newRSA.Sign(info, priKey)
	fmt.Println(infoSignedString + "\n")

	err := newRSA.VerifySignature(info, pubKey, infoSignedString)
	fmt.Println(err)

}
