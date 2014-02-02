package pgocrypto

import (
	_ "github.com/lib/pq"

	"database/sql"
	"testing"
)

func openDBConn(t *testing.T) *sql.DB {
	db, err := sql.Open("postgres", "sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	err = db.Ping()
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func TestEncryptDecryptThroughDB(t *testing.T) {
	db := openDBConn(t)
	defer db.Close()

	key := []byte("\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")
	testVector :=
		`Through the forest have I gone.
But Athenian found I none,
On whose eyes I might approve
This flower's force in stirring love.
Night and silence..Who is here?
Weeds of Athens he doth wear:
This is he, my master said,
Despised the Athenian maid;
And here the maiden, sleeping sound,
On the dank and dirty ground.
Pretty soul! she durst not lie
Near this lack-love, this kill-courtesy.
Churl, upon thy eyes I throw
All the power this charm doth owe.
When thou wakest, let love forbid
Sleep his seat on thy eyelid:
So awake when I am gone;
For I must now to Oberon.`

	var bin []byte
	err := db.QueryRow("SELECT pgo_encrypt($1, $2)", testVector, key).Scan(&bin)
	if err != nil {
		t.Fatal(err)
	}
	binValue, err := Decrypt(bin, key)
	if err != nil {
		t.Fatal(err)
	}
	strValue := string(binValue)
	if strValue != testVector {
		t.Fatalf("unexpected %s", strValue)
	}

	var str string
	err = db.QueryRow("SELECT pgo_encrypt_string($1, $2)", testVector, key).Scan(&str)
	if err != nil {
		t.Fatal(err)
	}
	strValue, err = DecryptString(str, key)
	if err != nil {
		t.Fatal(err)
	}
	if strValue != testVector {
		t.Fatalf("unexpected %s", strValue)
	}

	binValue, err = Encrypt([]byte(testVector), key)
	if err != nil {
		t.Fatal(err)
	}
	err = db.QueryRow("SELECT pgo_decrypt($1, $2)", binValue, key).Scan(&strValue)
	if err != nil {
		t.Fatal(err)
	}
	if strValue != testVector {
		t.Fatalf("unexpected %s", strValue)
	}

	str, err = EncryptString(testVector, key)
	if err != nil {
		t.Fatal(err)
	}
	err = db.QueryRow("SELECT pgo_decrypt_string($1, $2)", str, key).Scan(&strValue)
	if err != nil {
		t.Fatal(err)
	}
	if strValue != testVector {
		t.Fatalf("unexpected %s", strValue)
	}
}
