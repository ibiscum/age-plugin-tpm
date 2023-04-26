package plugin

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/foxboron/age-plugin-tpm/internal/bech32"
	"github.com/google/go-tpm/tpmutil"
)

type PINStatus int64

const (
	NoPIN PINStatus = iota
	HasPIN
)

func (p PINStatus) String() string {
	switch p {
	case NoPIN:
		return "NoPIN"
	case HasPIN:
		return "HasPIN"
	}
	return "Not a PINStatus"
}

type Key struct {
	Version   uint8          `json:"version"`
	Handle    tpmutil.Handle `json:"handle"`
	PIN       PINStatus      `json:"pin"`
	Created   time.Time      `json:"created"`
	Identity  string         `json:"identity"`
	Recipient string         `json:"recipient"`
}

func (k *Key) HandleToString() string {
	return HandleToString(k.Handle)
}

func (k *Key) Serialize() []any {
	return []interface{}{
		&k.Version,
		&k.Handle,
	}
}

func DecodeKey(s string) (*Key, error) {
	var key Key
	hrp, b, err := bech32.Decode(s)
	if err != nil {
		return nil, err
	}
	if hrp != strings.ToUpper(IdentityPrefix) {
		return nil, fmt.Errorf("invalid hrp")
	}
	r := bytes.NewBuffer(b)
	for _, f := range key.Serialize() {
		if err := binary.Read(r, binary.BigEndian, f); err != nil {
			return nil, err
		}
	}
	return &key, nil
}

func EncodeKey(k *Key) (string, error) {
	var b bytes.Buffer
	for _, v := range k.Serialize() {
		if err := binary.Write(&b, binary.BigEndian, v); err != nil {
			return "", err
		}
	}
	s, err := bech32.Encode(strings.ToUpper(IdentityPrefix), b.Bytes())
	if err != nil {
		return "", err
	}
	return s, nil
}

var (
	keyText = `
# Handle: %s
# Created: %s
`
)

func Marshal(k *Key, w io.Writer) {
	s := fmt.Sprintf(keyText, k.HandleToString(), k.Created)
	s = strings.TrimSpace(s)
	fmt.Fprintf(w, "%s\n", s)
}

func MarshalIdentity(k *Key, w io.Writer) error {
	key, err := EncodeKey(k)
	if err != nil {
		return err
	}
	Marshal(k, w)
	fmt.Fprintf(w, "# Recipient: %s\n", strings.ToLower(k.Recipient))
	fmt.Fprintf(w, "\n%s\n", key)
	return nil
}

func MarshalRecipient(k *Key, w io.Writer) error {
	Marshal(k, w)
	fmt.Fprintf(w, "%s\n", strings.ToLower(k.Recipient))
	return nil
}
