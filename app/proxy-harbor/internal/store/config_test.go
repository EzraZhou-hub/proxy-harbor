package store

import (
	"bytes"
	"os"
	"proxyharbor/internal/domain"
	"testing"
)

func TestCorruptAndUnsupportedFilesArePreserved(t *testing.T) {
	for _, content := range []string{`not json`, `{"version":99}`, `{"version":1,"password":"should-not-be-accepted"}`} {
		t.Run(content, func(t *testing.T) {
			s := New(t.TempDir())
			original := []byte(content)
			if err := os.WriteFile(s.Path(), original, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Load(); err == nil {
				t.Fatal("invalid config accepted")
			}
			got, err := os.ReadFile(s.Path())
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, original) {
				t.Fatal("original file was overwritten")
			}
		})
	}
}

func TestPolicyClaimsCannotBePersisted(t *testing.T) {
	config := domain.DefaultConfig()
	config.Applications = append(config.Applications, domain.TargetApplication{
		ID: "chrome", Name: "Google Chrome", Compatibility: "verified",
	})
	if err := New(t.TempDir()).Save(config); err == nil {
		t.Fatal("unverified application can forge a protection claim")
	}
}
