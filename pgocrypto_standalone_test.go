package pgocrypto

import (
	"bytes"
	"testing"
)

func TestPkcsPadding(t *testing.T) {
	type testCase struct {
		input []byte
		expected []byte
	}

	tests := []testCase{
		{[]byte{},
			[]byte{16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16}},

		{[]byte{0},
			[]byte{0,15,15,15,15,15,15,15,15,15,15,15,15,15,15,15}},

		{[]byte{1,2},
			[]byte{1,2,14,14,14,14,14,14,14,14,14,14,14,14,14,14}},

		{[]byte{2,3,3},
			[]byte{2,3,3,13,13,13,13,13,13,13,13,13,13,13,13,13}},

		{[]byte{2,3,4,5},
			[]byte{2,3,4,5,12,12,12,12,12,12,12,12,12,12,12,12}},

		{[]byte{3,4,5,6,7},
			[]byte{3,4,5,6,7,11,11,11,11,11,11,11,11,11,11,11}},

		{[]byte{20,21,22,23,24,25,26,27,28,29,30,31,32,33,34},
			[]byte{20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,1}},

		{[]byte{40,42,44,46,48,50,52,54,56,58,60,62,64,66,68,70},
			[]byte{40,42,44,46,48,50,52,54,56,58,60,62,64,66,68,70,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16}},

		{[]byte{80,83,85,89,95,97,101,105,107,113,119,129,133,137,141,143,149},
			[]byte{80,83,85,89,95,97,101,105,107,113,119,129,133,137,141,143,149,15,15,15,15,15,15,15,15,15,15,15,15,15,15,15}},
	}

	for testno, test := range tests {
		blockSize := 16
		result := pkcsPad(test.input, blockSize)
		if !bytes.Equal(result, test.expected) {
			t.Errorf("failed padding in test #%d: %v != %v", testno, result, test.expected)
		}
		unpadded, err := pkcsUnpad(result, blockSize)
		if err != nil {
			t.Error(err)
		}
		if !bytes.Equal(unpadded, test.input) {
			t.Errorf("failed unpadding in test #%d: %v != %v", testno, unpadded, test.input)
		}
	}
}

func TestPkcsPaddingInvalidInputs(t *testing.T) {
	tests := [][]byte{
		{1},										// not the correct block size
		{},											// need at least one block of data
		{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,2},		// invalid padding size
		{0,1,2,3,4,5,6,7,8,9,6,6,5,6,6,6},			// single invalid byte in padding
	}

	for testno, input := range tests {
		blockSize := 16
		_, err := pkcsUnpad(input, blockSize)
		if err == nil {
			t.Errorf("failed test %d: expected error", testno)
		}
	}
}

func TestEncryption(t *testing.T) {
	tests := [][]byte{
		{99,9,65,15,174,228,180,238,253,77,202,63,143,153,178,49,63,202,255,26,26,17,241,147,87,238,70,147,105,200,64,38,48,226,135,179,176,143,137,45,107,249,73,161,160,63,156,215,178,47,87,167,106,24,108,135,209,225,33,209,86,23,253,63},
		{124,31,162,233,100,26,108,208,220,214,10,110,45,247,211,53,133,211,142,98,132,16,155,80,195,239,84,163,192,228,202,21},
		{118,198,97,122,248,144,44,134,186,215,168,56,112,167,41,5,172},
		{17,201,185,162,54,183,161,137,95,75,158,143,151,76,51,203},
		{198,142,71,227,154,140,0,90,199,55,130,157,109,206,59},
		{52,95,184,236,153,251,248},
		nil,
	}

	for testno1, input1 := range tests {
		for testno2, input2 := range tests {
			if input1 == nil {
				continue
			}

			input := input1
			if input2 != nil {
				input = append(input, input2...)
			}

			key := []byte{194,118,14,119,237,137,65,182,196,202,54,197,232,93,20,14,163,170,50,76,48,69,118,20,68,226,207,151,243,126,211,100}
			ciphertext, err := Encrypt(input, key)
			if err != nil {
				t.Fatal(err)
			}
			decrypted, err := Decrypt(ciphertext, key)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(decrypted, input) {
				t.Errorf("failed test %d / %d: %v != %v", testno1, testno2, decrypted, input)
			}
		}
	}
}

func TestStringEncryption(t *testing.T) {
	input := `Through the forest have I gone.
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

	key := []byte{43,230,20,255,145,150,115,232,100,236,124,113,94,68,224,55,242,198,181,141,184,141,60,0,42,175,12,173,210,142,104,6}
	encrypted, err := EncryptString(input, key)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := DecryptString(encrypted, key)
	if err != nil {
		t.Fatal(err)
	}
	if decrypted != input {
		t.Fatalf("%v != %v", input, decrypted)
	}
}
