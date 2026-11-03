package migrations

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestF193F195EmbeddedSQLContracts(t *testing.T) {
	tests := []struct {
		name      string
		version   int
		direction MigrationDirection
		hashes    []string
	}{
		{"043_up", 43, MigrationDirectionUp, []string{
			"e28f0cfc6af717203a9ea2864d6c7e0482b75d02516f2998c14206a09c16fa42",
			"a1cf6fca1e0b56120e5a7fdbaaeeb32a03ecc29276d60ba731e689b85f5555c5",
			"105fd878869c10615946e71a1c50cc2ebcdd69070cec0647f8640514d27086e7",
			"a735738d7eb040ef305bcda81645b9b4e99f06db05e86ecca64f591d3a584f97",
			"990542b6a042cd15b74439bb14bd17ef920cd465f7790ed281be7fe6f4532e7e",
			"5cc8cdf5439e0fae9d6de3829d59b0219817f598e604a5c07df67ec6277e14de",
			"a4fa5f3f07baadd3bf168d7307c83b1abff4bfd5a4a32b35202b151ddc633701",
			"267a32c36c40c60e6f0cb978a71e1ca738bac7b766e932e1dc4fa33045c9ce4e",
			"dfdd7604307c6434bb0361d556a40d1ee36059a96fd99c6990094b563e00024e",
			"ac96e1b8adcea53d6c8acc907ccec1922f88f54b4a1357f277bbccd5d7dac787",
			"db540b5f8296ab34e3ebc0d21bed5e9ee27abbf6afffc4ad328550f7735eb6bf",
			"c997895d2edb6720ce0d81462b8e5b9480f82790edcfdcf1c1d289d443af7f59",
			"58ff3d083dfcb66a65015c48f691c52bc35e46fd5f9108c6f446b0ba796978a6",
			"106aa801fc69f9631508475c26c3baed89db26fab492d7ebe65b5d103a3e217a",
			"04b756b466ba0951dc9ecd3bc7f25630e52c42749a8c52328bc6fe41c32c652a",
			"523f0cebaa42ecae1b7171a7022170584b805fa0d2ff5b0b0545e024385f7e3c",
		}},
		{"043_down", 43, MigrationDirectionDown, []string{
			"792e343047f1f97dc76a41d0f077ad1a3585120f1e8350ea5443616b14bdb8eb",
			"09cf627e3bd8d1ce0eb6d222898f312296e7b2520baeb5e949f2f8b7c5ba169c",
			"113922878d8fb5a43784b3bde2503139a8d77ccd497deb6d67956ad1fed1887d",
			"2ba95ebb6e5fc263a19f81f39badfd1eb09fb829e81a31c857ad971a0bfed1f1",
			"03726e55ca980524259dd7a52427e2e12fb1f96f9a701ee9441f9a4e059dcce1",
			"da34def532dfbe3f1038010d8a6355ab30c7478f4434bcaeab387ba77365970a",
			"4aa2247e9bcda84cf86ffe88feeeba573deb5f7cba01869622df995f9199f00f",
			"258719cc02a6556956fe70c3901e2cf89c0c7a82df5c08df14ef00205db9852e",
			"06152138b73ce2ba77752239d3bf0f7e1154702575ce995e795b579428a1148d",
			"5cff54f5a607f603202c857a1a2b584a0360bd5f416399a9ddd4ac891b9f3242",
			"92c819d630c4f256283e009b2f2185ccdf7fc60c6d0444e729eeefdcb5c11686",
			"3fd02ee51fca3fd7573a23c8e43cc4c88016a9055d259b13c21a3a48102ce1f8",
			"f546b699b986218254441bed11b6e6992251ca3cd1ec8949482a3e1835ed1628",
			"d37edb603e0b5b4003bb18c3ae4f1454c2077c1e507d0f68faaed0083a4b4366",
			"512a3ecea020f89fa792fea17a37d05f1fad98ccc20bebe8cdacf1eb5b875645",
			"470467727bcdc1b9816cba93f31c4b62e9bb895e152c208705a519168896fa13",
			"a1976b4238a56186e86b31326dc3af6a9aba3ed9ef9f39b9709d515bac484c2c",
		}},
		{"044_up", 44, MigrationDirectionUp, []string{
			"ada0d5a9c57f59e82575b6d5f34edce7beeea4cd253dcb70e6d8a4547b3aaafb",
			"c6f7c94fd452c787f8825768824192c2babf85cad8ac4265cf50ab2d02c57528",
			"b4f017513997d013cab661852d2ef461044398e940a2b65dfb234944c948731a",
		}},
		{"044_down", 44, MigrationDirectionDown, []string{
			"8556fc88e66fb33cf681b7491278d8fa70c361cf048d30c1f57157e8c7f130b7",
			"78ead8fc9c7fab2a768866216b3d6500e8828dc02fc011562782983cc8cc5605",
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
	if total != 38 {
		t.Fatalf("embedded statement total = %d, want 38", total)
	}
}
