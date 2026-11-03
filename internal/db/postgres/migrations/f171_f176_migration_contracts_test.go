package migrations

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestF171F176EmbeddedSQLContracts(t *testing.T) {
	tests := []struct {
		name      string
		version   int
		direction MigrationDirection
		hashes    []string
	}{
		{"032_up", 32, MigrationDirectionUp, []string{
			"1214982abf9db3ba98ec6bca2ad302d313a9a42bab91ab77eeae44ddee6ff861", "65d25f3c90879d27a374ab89fa545f38eb940b96892fd3a55cd8ca4a55d8fcc6", "07adeb505572742073d1219ae2d37a7e2f18b71a18ff7da50e51e6811115e8d0", "5e2f01d25aeb18040c0c5504c9f7c79c20478823d4a9eeddac0bc0ea73a833b7", "e9c9bcf5a13c2c248cbbe5ffb5ec7f3d294effb5c43616e55d4b3cbdcedb9979", "c85a7450345a0752b8bc039eafc15bee06e9a748f62369b489928f94fb858211", "b5f8facee23fee9f3895105e5dda3f6776ac49d7f5af8005608561a80b450072", "25d037ef77baf0e257f176901c7e866e97330d43ad8d82bfe1ae537b21306123", "0b51256df3ba33561ef083fcce35f5ea2a07b405ac241f6bc5a45d8667254267", "beb33de611ebd34fcad71a87dd8165f3eb8edc20805c8315ed5651a592429a32", "7bcd71bc8d45913464754ca836be940195ebab1f4e98bccdcd07b0dc6049d8dc", "95eb9b98cc3d5fdb0218a4cd231c6abb87084c87811f718e17f8bee6c9f072ec", "16699ff5fd491712829735e8c2539de437128234dcfbf1f640bb3db0541afb13", "9411e04decc5aa42d99e6956eb2f4376a8e75abc28573875d902613fbcfa4260", "606e4d54bfaa18a9c62aadefafffb351792b625bc74a01940e97abc8416a9dd2", "3d1ad06b3f72b060fcfd5c6c7616b849457ef0444b4b5e48f38a898b3d196e42", "fa7123c42b7b52e5d54b3d62aaae17029f402b62083aa2e7b8512ad7b3bb1189", "4013bc434455a126dafb6f18998adf96289a96d4dd50e47064b3a51985376ce3",
		}},
		{"032_down", 32, MigrationDirectionDown, []string{
			"beb33de611ebd34fcad71a87dd8165f3eb8edc20805c8315ed5651a592429a32", "0b51256df3ba33561ef083fcce35f5ea2a07b405ac241f6bc5a45d8667254267", "25d037ef77baf0e257f176901c7e866e97330d43ad8d82bfe1ae537b21306123", "b5f8facee23fee9f3895105e5dda3f6776ac49d7f5af8005608561a80b450072", "c96f24435aa059670b2663962e5b91b22817fc697c6804895c5c8e6286c16c43", "ac3e366822041fa2733742340f4405a71bdc0a0d79596fec12b18ad2f5a4f0a5",
		}},
		{"033_up", 33, MigrationDirectionUp, []string{
			"b47ee1b6e670f434969c3a8b5da9a98574bb475b6212cd604efeb408a4b5c509", "7768496178bd6db318ed5ce9442b887591f18caccb1ea163887aa96980dde0ac", "43c153da359aba7b273e425cf40e41af4b47152caa1bdc0df1e82c6e2e06137f", "2271f7c6e92538dcc5ea629a5f19b13dbbea1d61491c4e177fb88f8a0de71c97",
		}},
		{"033_down", 33, MigrationDirectionDown, []string{
			"4c8cbc8bf136f5ef7072ec9fd09d7d96545834ac6807756d5107f1eea402f736", "82dd3aeb92d9424c0dcdefeb4051a37574789105c2380adf78073281a89b5ab4", "9d1d63cde41d54f80018ef0038914523c48d0b3a382b3eec36ff3623052d9494", "294c91d0d0bf5d20e694b52f7075c48466dcd93e3a9ae51f96678a7117b55ee1",
		}},
		{"034_up", 34, MigrationDirectionUp, []string{
			"d98d242353d8019e7abb6345d1f811a270de7c48e5cb0267dfd43ceaecf04225", "9feb2416fc5f7288691687102f70bf50d226ce9e08fbdd64d84948617aeee035", "43f5b2d35dcc3a02fa3f8314b1cfdf128efa76fc109c975bf44eb5f6749a6bd8", "f9924fb956db981b23aa94a75f1635ef0ec51572667ca57efbb166345045ab68", "9b9127f5a0ad814f8626fa4c6f5c2dc8b8546df6f96c69c5372d819840370868", "b1c481b477158ebe3021dd33ac9b97667c8d5facf29e044c33641544a4070030", "33e5f06db3aa25d5a9b583fd3d6d3fddeef55fcc1a9e9994e848100c28151c03", "2b458286f35283f7c8c3ae218caedd8219b4521ab7e74e9243e2c57fa54b1b21", "cd8dce2b038d7d55707e94fc5862a9c87d3393dc0b47c5940648b1e5336e04ff", "873f1fecc041b1eac2f0871a05ca53fd46f2bf96f8952268a4e6aadefe6a5219", "9ca601db5333e7eb4de04c0475febaba123d79c4b34596e3fb17d2da536c0b16",
		}},
		{"034_down", 34, MigrationDirectionDown, []string{
			"87f9449ec7fd0c696f923c14d083dd1be5de33b0b9fe22dd170feb34aa7b5f0f", "ccf5fb8c030017cf9ad2816c4bc5450eb1e39bf8531d15d803d8f521a4c9802f", "4d4d6c62654bd69a8431045a3e8c751c209d4b6b965998950a45f57c0ef12eee", "dd99776c96b8e52609f92f21a6210d8fd63d611c37dc5d5994a3bc2c24f8e52d", "3f4091c87dd9667ccd760ac16c310bf154592b81dcb710622c7a423bf6fba20e",
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
	if total != 48 {
		t.Fatalf("embedded statement total = %d, want 48", total)
	}
}
