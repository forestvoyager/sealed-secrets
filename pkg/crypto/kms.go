package crypto

import (
	"go.mozilla.org/sops/v3/kms"
)

// DecryptWithKMS decrypts the ciphertext with AWS KMS ARN and returns the result.
func DecryptWithKMS(ciphertext string, arn string, context string) ([]byte, error) {
	k := kms.NewMasterKeyFromArn(arn, kms.ParseKMSContext(context), "")
	k.EncryptedKey = ciphertext
	return k.Decrypt()
}
