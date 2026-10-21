// SPDX-License-Identifier: Apache-2.0
package patch

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"runtime"
)

func Generate(path string) error {
	pub, priv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return e
	}
	b, _ := json.Marshal(priv)
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(b)
	closeErr := f.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	b, _ = json.Marshal(pub)
	f, e = os.OpenFile(path+".pub", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if e != nil {
		return e
	}
	_, e = f.Write(b)
	f.Close()
	return e
}
func Private(path string) (ed25519.PrivateKey, error) {
	if runtime.GOOS != "windows" {
		st, e := os.Stat(path)
		if e != nil {
			return nil, e
		}
		if st.Mode().Perm()&0077 != 0 {
			return nil, ErrInvalid
		}
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	var k ed25519.PrivateKey
	if json.Unmarshal(b, &k) != nil || len(k) != 64 {
		return nil, ErrInvalid
	}
	return k, nil
}
func Public(path string) (ed25519.PublicKey, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	var k ed25519.PublicKey
	if json.Unmarshal(b, &k) != nil || len(k) != 32 {
		return nil, ErrInvalid
	}
	return k, nil
}
