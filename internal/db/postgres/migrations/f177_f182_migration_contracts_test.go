package migrations

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestF177F182EmbeddedSQLContracts(t *testing.T) {
	tests := []struct {
		name      string
		version   int
		direction MigrationDirection
		hashes    []string
	}{
		{"035_up", 35, MigrationDirectionUp, []string{
			"5ebdf54c4f77c6747da35abfdf5ca390071b312beccae5165d9f15446b2df2a4", "aa75e0ea509bdc625c0d52845217799027a5a66438f340109f835c5b4af8394f", "96ffe2dfd62e6ab37ba11994413ca799a1ca25c7198032ec0bd5240410add7fb", "1bd81abb860f8e51916d9c32f92e228641a7dcd4872e63e67c49076414ef3294", "5424299ffa04da5a06761af7c3a169ed0cf50d454bb5a7b9ef8f534dcccaf868", "8ca8f507a80e630a3f8632d84e07d4358b9f58c594e8d7fa99d13178bb00db33",
		}},
		{"035_down", 35, MigrationDirectionDown, []string{
			"82fd6a658198a77b2d44acb05abca3b2abf929a5f3b8e3c521d1361e7bf02224", "627ca072f35d57e644968bafcc4d79e2ef2714b69e29bf496cb6e2a04b0a5cb4", "62346e1cb620513e01cf12eba2797b5b366e75b43030b372397b755845a53700", "ab7685045bb54adbee922d6d8723c3cfb5bb9b0620b3cbcd5a2fed66a8d3c300", "4ffff08f840ad15000c8ebc18bbf80dc0e3f936847dd0e824bea6fa2e81869e4", "c046ff62464e24e7e38e3838e781a3d908de958907c884f85c3e5afc78508809",
		}},
		{"036_up", 36, MigrationDirectionUp, []string{
			"ebe5a1c62d3a006c6fa231af5cdd73687a19408557a05b40af223b9a9fbed6e9", "c875d1b01f075c4bc525b30b523e5078aa196768b69caae26f778b9c3c254cac",
		}},
		{"036_down", 36, MigrationDirectionDown, []string{
			"8f5171ebf4fa087c320ad9669c88cbb81d677f04147a37c0df7f2a28e9359234",
		}},
		{"037_up", 37, MigrationDirectionUp, []string{
			"70303a4c960ddf140959e1da21759af65a76d7259c654bcdcf0867e51d15ebad",
		}},
		{"037_down", 37, MigrationDirectionDown, []string{
			"a3e1097577eb84d8048d1ddaa9b8fc15f5f9a18de2025497b5721b2d52df9a72",
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
	if total != 17 {
		t.Fatalf("embedded statement total = %d, want 17", total)
	}
}
