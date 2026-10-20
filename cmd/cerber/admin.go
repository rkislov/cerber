// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/rkislov/cerber/internal/admin"
	"github.com/rkislov/cerber/internal/storage/sqlite"
	"io"
	"os"
	"path/filepath"
	"strings"
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

func adminUserAdd(ctx context.Context, store *sqlite.Store, args []string, out, errOut io.Writer) error {
	f := flags("siem user-add", errOut)
	name := f.String("username", "", "unique lowercase username")
	role := f.String("role", "viewer", "administrator, operator or viewer")
	file := f.String("password-file", "", "private UTF-8 password file (12–256 bytes)")
	if err := parse(f, args); err != nil {
		return err
	}
	if *file == "" {
		return fmt.Errorf("password file required")
	}
	source, err := os.Open(*file)
	if err != nil {
		return err
	}
	defer source.Close()
	data, err := io.ReadAll(io.LimitReader(source, 259))
	if err != nil {
		return err
	}
	if len(data) > 258 {
		return fmt.Errorf("password file too large")
	}
	hash, err := admin.HashPassword(strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r"))
	if err != nil {
		return err
	}
	if err = store.AdminCommand(ctx, admin.Command{Action: "user.create", Username: *name, Role: *role, PasswordHash: hash}); err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(map[string]string{"username": *name, "role": *role})
}
