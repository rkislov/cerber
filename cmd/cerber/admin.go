// SPDX-License-Identifier: Apache-2.0
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func adminKeygen(args []string, out, errOut io.Writer) error {
	f := flags("siem admin-keygen", errOut)
	file := f.String("out", "", "new administrator key JSON file")
	if err := parse(f, args); err != nil {
		return err
	}
	if *file == "" {
		return fmt.Errorf("output key path required")
	}
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return err
	}
	data, _ := json.MarshalIndent(map[string]string{"token": hex.EncodeToString(secret[:])}, "", "  ")
	if err := os.MkdirAll(filepath.Dir(*file), 0700); err != nil {
		return err
	}
	dest, err := os.OpenFile(*file, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = dest.Write(data)
	if err == nil {
		err = dest.Sync()
	}
	closeErr := dest.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(*file)
		return err
	}
	return json.NewEncoder(out).Encode(map[string]string{"administrator_key_file": *file})
}
