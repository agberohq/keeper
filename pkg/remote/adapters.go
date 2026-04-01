package remote

import (
	"encoding/base64"
	"fmt"
	"net/http"
)

// VaultTransit returns a Config pre-populated for HashiCorp Vault's Transit
// secrets engine. address is the Vault server address (e.g. https://vault:8200),
// token is the Vault token, and keyName is the Transit key name.
func VaultTransit(address, token, keyName string) Config {
	base := fmt.Sprintf("%s/v1/transit", address)
	return Config{
		URL:                    fmt.Sprintf("%s/encrypt/%s", base, keyName),
		UnwrapURL:              fmt.Sprintf("%s/decrypt/%s", base, keyName),
		Method:                 http.MethodPost,
		Headers:                map[string]string{"X-Vault-Token": token},
		WrapRequestTemplate:    `{"plaintext":"{{.DEK}}"}`,
		WrapResponseJSONPath:   "data.ciphertext",
		UnwrapRequestTemplate:  `{"ciphertext":"{{.Wrapped}}"}`,
		UnwrapResponseJSONPath: "data.plaintext",
	}
}

// AWSKMS returns a Config pre-populated for AWS Key Management Service.
// This adapter calls the AWS KMS HTTP API directly without the AWS SDK.
// region is the AWS region (e.g. us-east-1) and keyID is the KMS key ID or ARN.
// AWS SigV4 request signing is not handled here; use the Headers field to
// supply a pre-signed Authorization header or an AWS API Gateway pass-through token.
func AWSKMS(region, keyID string) Config {
	endpoint := fmt.Sprintf("https://kms.%s.amazonaws.com", region)
	encodedKey := base64.StdEncoding.EncodeToString([]byte(keyID))
	return Config{
		URL:                    endpoint,
		Method:                 http.MethodPost,
		Headers:                map[string]string{"Content-Type": "application/x-amz-json-1.1"},
		WrapRequestTemplate:    fmt.Sprintf(`{"KeyId":"%s","Plaintext":"{{.DEK}}"}`, encodedKey),
		WrapResponseJSONPath:   "CiphertextBlob",
		UnwrapRequestTemplate:  `{"CiphertextBlob":"{{.Wrapped}}"}`,
		UnwrapResponseJSONPath: "Plaintext",
	}
}

// GCPKMS returns a Config pre-populated for Google Cloud KMS.
// project, location, keyRing, and key identify the CryptoKey resource.
// Set Headers["Authorization"] = "Bearer <access-token>" before use.
func GCPKMS(project, location, keyRing, key string) Config {
	base := fmt.Sprintf(
		"https://cloudkms.googleapis.com/v1/projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s",
		project, location, keyRing, key,
	)
	return Config{
		URL:                    base + ":encrypt",
		UnwrapURL:              base + ":decrypt",
		Method:                 http.MethodPost,
		WrapRequestTemplate:    `{"plaintext":"{{.DEK}}"}`,
		WrapResponseJSONPath:   "ciphertext",
		UnwrapRequestTemplate:  `{"ciphertext":"{{.Wrapped}}"}`,
		UnwrapResponseJSONPath: "plaintext",
	}
}
