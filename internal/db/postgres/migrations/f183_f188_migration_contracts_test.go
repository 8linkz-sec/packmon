package migrations

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestF183F188EmbeddedSQLContracts(t *testing.T) {
	tests := []struct {
		name      string
		version   int
		direction MigrationDirection
		hashes    []string
	}{
		{"038_up", 38, MigrationDirectionUp, []string{
			"7d67aaae78f0bd40e624e5333f0ca5bce3e810d2deb7336ac5b94c7d17e62a82",
			"f9a24f9febc2e4df5c66d82e153cdd00f5cfda3407870e3824dd700e85700deb",
		}},
		{"038_down", 38, MigrationDirectionDown, []string{
			"04d1221bb67dbccb0a0488fe68f487cc3902373e7e7abb5bd7492bad0401bb54",
			"6769ae264928ab3a1e4df7e74fea2324c6f1ba07171730ffc51b5ba9322d1cdd",
		}},
		{"039_up", 39, MigrationDirectionUp, []string{
			"7a0c5bd4da15496e9cd1ad2bbfe2ecb20f8cf0bad9bf6fdbc639e0b0aa1d7ec3",
			"91df51ad236ac05b5baac41b4ba0f9cfb6c37cb331ff057b319cdc058e9ad0e1",
		}},
		{"039_down", 39, MigrationDirectionDown, []string{
			"27b4e6fcbb562544a11e2f4aed0bb888ec4eee6b5e54c9179360e476e86f920b",
		}},
		{"040_up", 40, MigrationDirectionUp, []string{
			"1fe3840ef2d58fafb325a3ef1a91ff8687c55eb58e13d021fc3c2020de87eea8",
		}},
		{"040_down", 40, MigrationDirectionDown, []string{
			"78b4e57713acaf1e879b34559d7b04792d14691844e13e75755800df566063e2",
		}},
	}

	total := 0
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			embedded, err := ReadEmbeddedMigration(tt.version, tt.direction)
			if err != nil {
				t.Fatalf("ReadEmbeddedMigration(%03d, %s): %v", tt.version, tt.direction, err)
			}
			migration := migrationFile{version: embedded.Version, name: embedded.Name, direction: embedded.Direction, sql: embedded.SQL}
			if !migrationRunsInTransaction(migration) {
				t.Fatalf("migration %03d %s is not transactional", tt.version, tt.direction)
			}
			statements, err := splitSQLStatements(embedded.SQL)
			if err != nil {
				t.Fatalf("splitSQLStatements(%03d, %s): %v", tt.version, tt.direction, err)
			}
			if len(statements) != len(tt.hashes) {
				t.Fatalf("statement count = %d, want %d", len(statements), len(tt.hashes))
			}
			for i, statement := range statements {
				normalized := strings.Join(strings.Fields(statement), " ")
				digest := sha256.Sum256([]byte(normalized))
				if got := hex.EncodeToString(digest[:]); got != tt.hashes[i] {
					t.Fatalf("statement %d digest = %s, want %s\nSQL: %s", i+1, got, tt.hashes[i], normalized)
				}
			}
		})
		total += len(tt.hashes)
	}
	if total != 9 {
		t.Fatalf("embedded statement total = %d, want 9", total)
	}
}
