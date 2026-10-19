// SPDX-License-Identifier: Apache-2.0
package knowledge

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// A directory lock serializes writers across processes. It is intentionally not
// stolen after a timeout: an operator must verify the old process is gone.
func lock(root string) (func(), error) {
	path := filepath.Join(root, ".write-lock")
	if err := os.Mkdir(path, 0700); err != nil {
		return nil, fmt.Errorf("knowledge directory busy or inaccessible (%s): %w", path, err)
	}
	return func() { _ = os.Remove(path) }, nil
}
func writeAtomic(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
func readLimited(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("content exceeds %d byte limit", limit)
	}
	return data, nil
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r contextReader) Read(b []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(b)
}
func verifyFile(ctx context.Context, path string, m Manifest) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() != m.Size {
		return fmt.Errorf("cached package size mismatch")
	}
	h := sha256.New()
	n, err := io.Copy(h, contextReader{ctx, io.LimitReader(f, m.Size+1)})
	if err != nil {
		return err
	}
	if n != m.Size || hex.EncodeToString(h.Sum(nil)) != m.Snapshot.SHA256 {
		return fmt.Errorf("knowledge package SHA-256 mismatch")
	}
	return nil
}

// validateXML checks structural well-formedness only, not the BDU record schema.
func validateXML(ctx context.Context, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	reader := bufio.NewReader(contextReader{ctx, f})
	if prefix, err := reader.Peek(3); err == nil && bytes.Equal(prefix, []byte{0xef, 0xbb, 0xbf}) {
		if _, err = reader.Discard(3); err != nil {
			return err
		}
	}
	d := xml.NewDecoder(reader)
	depth, roots := 0, 0
	for {
		token, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("invalid knowledge XML: %w", err)
		}
		switch v := token.(type) {
		case xml.StartElement:
			if depth == 0 {
				roots++
			}
			depth++
			if depth > 128 || roots > 1 {
				return fmt.Errorf("XML exceeds root/depth limits")
			}
		case xml.EndElement:
			depth--
		case xml.Directive:
			return fmt.Errorf("XML directives/DTD are not allowed")
		case xml.CharData:
			if depth == 0 && strings.TrimSpace(string(v)) != "" {
				return fmt.Errorf("XML text outside root")
			}
		}
	}
	if roots != 1 || depth != 0 {
		return fmt.Errorf("XML requires exactly one root")
	}
	return nil
}
