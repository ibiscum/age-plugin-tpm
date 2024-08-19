package plugin

import (
	"bytes"
	"crypto/cipher"
	"crypto/ecdh"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/google/go-tpm/tpm2/transport/simulator"
)

func TestEncryptionDecryption(t *testing.T) {
	tpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("failed opening tpm: %v", err)
	}
	defer tpm.Close()

	cases := []struct {
		msg        string
		filekey    []byte
		pin        []byte
		decryptpin []byte
		shouldfail bool
	}{
		{
			msg:     "test encryption/decrypt - no pin",
			filekey: []byte("this is a test filekey"),
		},
		{
			msg:        "test encryption/decrypt - pin",
			filekey:    []byte("this is a test filekey"),
			pin:        []byte("123"),
			decryptpin: []byte("123"),
		},
		{
			msg:        "test encryption/decrypt - no pin for decryption",
			filekey:    []byte("this is a test filekey"),
			pin:        []byte("123"),
			shouldfail: true,
		},
		{
			msg:        "test encryption/decrypt - no pin for key, pin for decryption",
			filekey:    []byte("this is a test filekey"),
			pin:        []byte(""),
			decryptpin: []byte("123"),
			shouldfail: true,
		},
	}

	for n, c := range cases {
		t.Run(fmt.Sprintf("case %d, %s", n, c.msg), func(t *testing.T) {
			identity, recipient, err1 := CreateIdentity(tpm, c.pin)

			wrappedFileKey, sessionKey, err2 := EncryptFileKey(c.filekey, recipient.Pubkey)

			unwrappedFileKey, err3 := DecryptFileKeyTPM(tpm, identity, sessionKey, wrappedFileKey, c.decryptpin)

			err := errors.Join(err1, err2, err3)

			if err != nil {
				if c.shouldfail {
					return
				}
				t.Fatalf("failed test: %v", err)
			}

			if c.shouldfail {
				t.Fatalf("test should be failing")
			}

			if !bytes.Equal(c.filekey, unwrappedFileKey) {
				t.Fatalf("filkeys are not the same")
			}
		})
	}
}

func Test_kdf(t *testing.T) {
	type args struct {
		sharedKey *ecdh.PublicKey
		publicKey *ecdh.PublicKey
		shared    []byte
	}
	tests := []struct {
		name    string
		args    args
		want    cipher.AEAD
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := kdf(tt.args.sharedKey, tt.args.publicKey, tt.args.shared)
			if (err != nil) != tt.wantErr {
				t.Errorf("kdf() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("kdf() = %v, want %v", got, tt.want)
			}
		})
	}
}
