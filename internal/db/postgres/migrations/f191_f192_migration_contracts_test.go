package migrations

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestF191F192EmbeddedSQLContracts(t *testing.T) {
	tests := []struct {
		name      string
		direction MigrationDirection
		hashes    []string
	}{
		{"042_up", MigrationDirectionUp, []string{
			"ccf5fb8c030017cf9ad2816c4bc5450eb1e39bf8531d15d803d8f521a4c9802f",
			"4d4d6c62654bd69a8431045a3e8c751c209d4b6b965998950a45f57c0ef12eee",
			"dd99776c96b8e52609f92f21a6210d8fd63d611c37dc5d5994a3bc2c24f8e52d",
			"3f4091c87dd9667ccd760ac16c310bf154592b81dcb710622c7a423bf6fba20e",
			"a45c57bd36d6e774a1c1e7e9ad8e6a18860893095488e520a2814d320ea17588",
			"24ba738759809916e508271b1102add8d2b1143f2ef37965d37f9df8a2f05ceb",
			"08cd2870b4b0d3a97a7dcfc6a25a2e2ac6ab855df1d3359292e5cf1d085de3bb",
			"c420abbc69b4abb2ec0adf199b4cc1bf53b161ce533bde5c9d08b973c9b2f7f6",
			"7ce90d07ab4e54034c134bfe4f5171ceedc8f6e4ffe811d507e7c837c5cb0570",
			"efc9be91d732db6a79c792ce6d8196ea4e9f4c3f07eed9937a929384110938af",
			"07a42dad6f843fb9f93f66b25e3d7e1a06f7219a6e14b78e37527ef74e2d25ac",
			"d3acaf199603761ce5f5076be49175424ec2797aa935af5a680a82009b710362",
			"49697705527234c419169e8cff2fb3fcda3f7fea73f8ce73ab6fb5521f45c12f",
			"14fba9e2bc1076d42b385a8ebe304a4d9b885ce76343c7384b7eeb12c8c1f294",
			"c9497a0fbf1c5300c1af091c4513d0f7417d8167868bd205fe722348e5517a88",
			"fdb3920d1a8c602b805be28bb6323c507aeee626fa67136113767b262cb379aa",
			"acac507b87f567b8b03074fffcb6d0d94808b568f2998e6f5e8a0fbcda6ac243",
			"45896184d6842eaf2b7ef73381367cffd1b7bfe093212f0af2c5dc50205786b9",
			"09bcebec2b61ca7f4c3f0cdb012be850b01ddc4289c8d5f49aee6d4ff7f91e4a",
			"ac9c7d3171fb2b725731ebf189004d53179a1ebcfc2971618e385d60cff35cd2",
			"33e5f06db3aa25d5a9b583fd3d6d3fddeef55fcc1a9e9994e848100c28151c03",
			"2b458286f35283f7c8c3ae218caedd8219b4521ab7e74e9243e2c57fa54b1b21",
			"cd8dce2b038d7d55707e94fc5862a9c87d3393dc0b47c5940648b1e5336e04ff",
			"873f1fecc041b1eac2f0871a05ca53fd46f2bf96f8952268a4e6aadefe6a5219",
			"eccf46e1d3d7f8fa51c921bf0f72f3574842c6473d082a06ee79bcb790a3b73a",
			"26992db4ffb7b2c666ad7358316f931eaf76774b7ec3487f1690bcc21036acb2",
			"c7c05bd0c549162ccc6eb1c4ef7b56f8d69c9935078716b587647fd8477d2990",
			"7cf3efa044083c5a0c0345793bcb1888b86a31615e8dfceaf6b32bf35f98dfec",
			"4fa1b2cf788c7293626a8e5ba6bf393fcbfbab5a6f09c744f2895903e75536d6",
			"87925628754406c3bf436fbecf83d6160ab9a4271429bdd8a51ff7926ab73c36",
			"0586ce28eb9d27aef2c878be4f29041b5ad70c27cb06f036f21f600c9db94806",
			"1c0d2c8adf535d96c654b6f3c2e9c57ae7a5594870ad0f6f5931a09afab77fdb",
			"acaf4b26d2bd5cc1842646a8c41392e3d9be36b6967b42dc83e075f6df1dbf7f",
			"0ab5ff1fcf8bee5307b14b0f50891b4a028b4f8ca20b94aeeae322f7b0012a15",
			"23af6a2c98875b6bd764a435974f9e8fdfdc8c73f08a8a644e11374982ac317f",
			"efb4f789ab1dd80f63ea472505349265cb9e7c80c77e97081f126b0291b26a86",
			"a490ff2232d63c510bc1ca08deff86e6bdfa2a8834539c38c24f28515442e299",
			"ba12e45fdd8dd21d88bdb6cd57cabba152e0eb40693162dcc1f1094f1dffb43b",
			"69db2ef2a87805aa3051f9a655655ff1db098efbf86eeb1a5462b81f2c16094f",
			"7758390a247f97aa9be1467a94e7321f71313e4471ceb6592301de6ed49feb45",
			"3dc5626aa8e2148e1765799b81f8d77eab0c940b453e6adbee40915a8a34eb2b",
			"ef1732e2ec121c0a3a027ddfe2a3cfeda0b7132b43ddb42172bffbf406729195",
		}},
		{"042_down", MigrationDirectionDown, []string{
			"7ce90d07ab4e54034c134bfe4f5171ceedc8f6e4ffe811d507e7c837c5cb0570",
			"c420abbc69b4abb2ec0adf199b4cc1bf53b161ce533bde5c9d08b973c9b2f7f6",
			"be99ad24f01f2c8f6fa7a73d19e840f5f1821333306841761f131515b6b694dd",
			"a45c57bd36d6e774a1c1e7e9ad8e6a18860893095488e520a2814d320ea17588",
			"24ba738759809916e508271b1102add8d2b1143f2ef37965d37f9df8a2f05ceb",
			"ccf5fb8c030017cf9ad2816c4bc5450eb1e39bf8531d15d803d8f521a4c9802f",
			"4d4d6c62654bd69a8431045a3e8c751c209d4b6b965998950a45f57c0ef12eee",
			"dd99776c96b8e52609f92f21a6210d8fd63d611c37dc5d5994a3bc2c24f8e52d",
			"3f4091c87dd9667ccd760ac16c310bf154592b81dcb710622c7a423bf6fba20e",
			"030dea2fa41033aa076564b4048012d3145cef08c5e225ac546edb362d5ced01",
			"acac507b87f567b8b03074fffcb6d0d94808b568f2998e6f5e8a0fbcda6ac243",
			"34f65fe964efafbba5d42ef6735268abfc847fac27da105824f3a30ffae8a430",
			"eccf46e1d3d7f8fa51c921bf0f72f3574842c6473d082a06ee79bcb790a3b73a",
			"26992db4ffb7b2c666ad7358316f931eaf76774b7ec3487f1690bcc21036acb2",
			"33e5f06db3aa25d5a9b583fd3d6d3fddeef55fcc1a9e9994e848100c28151c03",
			"2b458286f35283f7c8c3ae218caedd8219b4521ab7e74e9243e2c57fa54b1b21",
			"cd8dce2b038d7d55707e94fc5862a9c87d3393dc0b47c5940648b1e5336e04ff",
			"873f1fecc041b1eac2f0871a05ca53fd46f2bf96f8952268a4e6aadefe6a5219",
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			embedded, err := ReadEmbeddedMigration(42, tt.direction)
			if err != nil {
				t.Fatalf("ReadEmbeddedMigration(042, %s): %v", tt.direction, err)
			}
			migration := migrationFile{version: embedded.Version, name: embedded.Name, direction: embedded.Direction, sql: embedded.SQL}
			if !migrationRunsInTransaction(migration) {
				t.Fatalf("migration %s is not transactional", migration.name)
			}
			statements, err := splitSQLStatements(embedded.SQL)
			if err != nil {
				t.Fatalf("splitSQLStatements(%s): %v", migration.name, err)
			}
			if len(statements) != len(tt.hashes) {
				t.Fatalf("%s statement count = %d, want %d", migration.name, len(statements), len(tt.hashes))
			}
			for i, statement := range statements {
				normalized := strings.Join(strings.Fields(statement), " ")
				digest := sha256.Sum256([]byte(normalized))
				if got := hex.EncodeToString(digest[:]); got != tt.hashes[i] {
					t.Fatalf("%s statement %d digest = %s, want %s\nSQL: %s", migration.name, i+1, got, tt.hashes[i], normalized)
				}
			}
		})
	}
}
