package proj2

import (
	"fmt"
	"github.com/nweaver/cs161-p2/userlib"
	"github.com/texttheater/golang-levenshtein/levenshtein"
	"math/rand"
	"strconv"
	"time"
)
import "testing"
import "reflect"

func Shuffler(vals []byte) []byte {
	//Simple array shuffler
	//Code re-purposed from:
	//https://www.calhoun.io/how-to-shuffle-arrays-and-slices-in-go/
	r := rand.New(rand.NewSource(time.Now().Unix()))
	ret := make([]byte, len(vals))
	n := len(vals)
	for i := 0; i < n; i++ {
		randIndex := r.Intn(len(vals))
		ret[i] = vals[randIndex]
		vals = append(vals[:randIndex], vals[randIndex+1:]...)
	}
	return ret
}

func InStringArray(a string, list []string) bool {
	//Simple linear search of a string array
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func TestInit(t *testing.T) {
	t.Log("Initialization test")
	userlib.DebugPrint = true
	someUsefulThings()

	userlib.DebugPrint = false
	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
	}
	// t.Log() only produces output if you run with "go test -v"
	t.Log("Got user", u)
}

func TestStorageAppend(t *testing.T) {

	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}
	t.Log("Loaded user", u)

	v := []byte("This is a test")
	u.StoreFile("file1", v)
	app1 := []byte(", This is the part appended")
	u.AppendFile("file1", app1)
	v = append(v, app1...)
	app2 := []byte(", appending again...")
	u.AppendFile("file1", app2)
	v = append(v, app2...)

	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
	}
}

func TestShareUpdateRevokeReshareTransitive(t *testing.T) {
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
	}

	u3, err3 := InitUser("carol", "fckbar")
	if err3 != nil {
		t.Error("Failed to initialize carol", err3)
	}

	var v, v1, v2, v3 []byte
	var msgid string

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to load the file from alice", err)
	}

	msgid, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share file with bob", err)
	}
	err = u2.ReceiveFile("file2", "alice", msgid)
	if err != nil {
		t.Error("bob failed to receive the share message", err)
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("bob failed to download the file after sharing", err)
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("bob: Shared file is not the same", v, v2)
	}

	// MY ADDITION -----------------------------------------------------

	// Share file with Carol (tried with both Bob's and Alice's sharing msgid)
	msgid, err = u.ShareFile("file1", "carol")
	if err != nil {
		t.Error("Failed to share file with carol", err)
	}
	err = u3.ReceiveFile("file3", "alice", msgid)
	if err != nil {
		t.Error("carol failed to receive the share message", err)
	}

	v3, err = u3.LoadFile("file3")
	if err != nil {
		t.Error("carol failed to download the file after sharing", err)
	}
	if !reflect.DeepEqual(v, v3) {
		t.Error("carol: Shared file is not the same", v, v3)
	}

	// Carol appends
	app := []byte("shared appending now")
	u3.AppendFile("file3", app)
	v = append(v, app...)

	v1, err = u.LoadFile("file1")
	if err != nil {
		t.Error("alice failed to download the file after carol appended", err)
	}
	if !reflect.DeepEqual(v, v1) {
		t.Error("alice: appended file is not the same", v, v1)
	}
	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("bob failed to download the file after carol appended", err)
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("bob: appended file is not the same", v, v2)
	}

	// Bob rewrites
	v = []byte("Bob is king.")
	u2.StoreFile("file2", v)
	v1, err = u.LoadFile("file1")
	if err != nil {
		t.Error("alice failed to download the file after bob rewrote", err)
	}
	if !reflect.DeepEqual(v, v1) {
		t.Error("alice: rewritten file is not the same", v, v1)
	}
	v3, err = u3.LoadFile("file3")
	if err != nil {
		t.Error("carol failed to download the file after bob rewrote", err)
	}
	if !reflect.DeepEqual(v, v3) {
		t.Error("carol: rewritten file is not the same", v, v3)
	}

	// Bob revokes
	err = u2.RevokeFile("file2")
	if err != nil {
		t.Error("Could not revoke: ", err)
	}
	// Bob accessing revoked file
	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after revoking", err)
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("File after revoking is not the same", v, v2)
	}

	// Shared people accessing revoked file
	chk, err := u.LoadFile("file1")
	if err == nil || chk != nil {
		t.Error("Shared people can still access revoked file")
	}
	chk, err = u3.LoadFile("file3")
	if err == nil || chk != nil {
		t.Error("Shared people can still access revoked file")
	}

	// Bob reshares with Carol after revoke
	msgid, err = u2.ShareFile("file2", "carol")
	if err != nil {
		t.Error("Failed to share file with carol", err)
	}
	err = u3.ReceiveFile("file3", "bob", msgid)
	if err != nil {
		t.Error("carol failed to receive the share message", err)
	}
	v3, err = u3.LoadFile("file3")
	if err != nil {
		t.Error("carol failed to download the file after sharing", err)
	}
	if !reflect.DeepEqual(v, v3) {
		t.Error("carol: Shared file is not the same", v, v3)
	}

}

func TestGetUser(t *testing.T) {
	t.Log("Starting test")
	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
	}
	b, er := GetUser("alice", "fubar")
	if er != nil {
		// t.Error says the test fails
		t.Error("Failed to get user", er)
	}
	t.Log("Got user")
	if u.Username != b.Username {
		t.Error("Users not matching up")
	}
	t.Log("Test Passed")
}

func TestFailGetUser(t *testing.T) {
	t.Log("Starting test")
	u, err := InitUser("alice", "fubar")
	if (err != nil) || (u == nil) {
		t.Error("Failed to initialize user", err)
	}

	//Now trying users NOT in system
	t.Log("Trying users NOT in system.")
	b, e := GetUser("Alice", "fubar")
	if (e == nil) || (b != nil) {
		t.Error("Failed to identify user not in system.", e)
	}
	c, err_one := GetUser("alice", "rabuf")
	if (err_one == nil) || (c != nil) {
		t.Error("Failed to identify user not in system.", err_one)
	}
	t.Log("Test Passed")
}

func TestGetFile(t *testing.T) {
	t.Log("Starting test")
	t.Log("Initializing user")
	u, err := InitUser("alice", "fubar")
	if (err != nil) || (u == nil) {
		t.Error("Failed to initialize user", err)
	}
	t.Log("Storing file")
	var testfile = []byte("will we find this again")
	u.StoreFile("testfile", testfile)
	t.Log("Attempting to load file")
	loadfile, err_one := u.LoadFile("testfile")
	if err_one != nil {
		t.Error("Failed to load our file again")
	}
	if !reflect.DeepEqual(testfile, loadfile) {
		t.Error("Files do not match")
	}



	t.Log("Initializing our naive attacker")
	//Naive attacker simply tries to access file by filename.
	//He should be unsuccessful.
	a, err_two := InitUser("attacker", "naive")
	if (err_two != nil) || (a == nil) {
		t.Error("Failed to initialize user", err)
	}
	lfile, err_three := a.LoadFile("testfile")
	if (err_three == nil) || (lfile != nil) {
		t.Error("Naive attacker somehow able to access our file...", err_three)
	}



	t.Log("Starting missed file")
	//Alice tries to get file she has no access to...
	nofile, err_four := a.LoadFile("NoSuchFile")
	if (err_four == nil) || (nofile != nil) {
		t.Error("Somehow able to access file that doesn't exist. Either Alice must be a magician, or you messed up...", err_four)
	}
}

func TestHeavyUser(t *testing.T) {
	//Tests if user tries to make a lot of loads then tries to get them all.
	//Will any issues come about?

	t.Log("Starting test")
	t.Log("Initializing user")
	u, err := InitUser("alice", "fubar")
	if (err != nil) || (u == nil) {
		t.Error("Failed to initialize user", err)
	}

	t.Log("Storing files")
	for i := 0; i < 100; i++ {
		//Create byte array that contains the singular number
		var filename = strconv.Itoa(i)
		var temp = []byte(filename)
		u.StoreFile(filename, temp)
	}
	t.Log("Loading and Checking files")
	// Now lets check if any issues arose!
	for i := 0; i < 100; i++ {
		//Create byte array that contains the singular number
		var filename = strconv.Itoa(i)
		var check = []byte(filename)
		file_out, err := u.LoadFile(filename)
		if err != nil {
			t.Error("Error loading file with name:" + filename)
		}
		if !reflect.DeepEqual(check, file_out) {
			t.Error("Files do not match. Filename: " + filename)
		}
	}

	t.Log("Successfully was able to store/load large numbers of files")
}

func TestHeavyDNE(t *testing.T) {
	//Checks to make sure under heavy loads we don't
	//magically make a file appear out of nowhere.
	t.Log("Starting test")
	t.Log("Initializing user")
	u, err := InitUser("alice", "fubar")
	if (err != nil) || (u == nil) {
		t.Error("Failed to initialize user", err)
	}

	for i := 0; i < 100; i++ {
		//Create byte array that contains the singular number
		var filename = strconv.Itoa(i)
		file_out, err := u.LoadFile(filename)
		if (err == nil) || (file_out != nil) {
			t.Error("Somehow loaded file with name:" + filename)
		}
	}
}

func TestHeavyUsers(t *testing.T) {
	//Same as TestHeavyUser,
	//but now there is ten times the potential issues!
	t.Log("Starting test")
	t.Log("Initializing users and storing files")
	for u := 0; u < 10; u++ {
		var username = strconv.Itoa(u)
		u, err := InitUser(username, "fubar")
		if (err != nil) || (u == nil) {
			t.Error("Failed to initialize user", err)
		}
		for i := 0; i < 100; i++ {
			var filename = strconv.Itoa(i)
			var temp = []byte(filename)
			u.StoreFile(filename, temp)
		}
	}
	t.Log("Loading users, Loading files, and check them")
	for u := 0; u < 10; u++ {
		var username = strconv.Itoa(u)
		user, er := GetUser(username, "fubar")
		if (er != nil) || (user == nil) {
			t.Error("Failed to get user", er)
		}
		for i := 0; i < 100; i++ {
			var filename = strconv.Itoa(i)
			var temp = []byte(filename)
			out, err_temp := user.LoadFile(filename)
			if err_temp != nil {
				t.Error("Error loading file")
			}
			if !reflect.DeepEqual(temp, out) {
				t.Error("Files do not match. Filename: " + filename)
			}
		}
	}
	t.Log("Test completed")
}

func TestLongKeysLargeFiles(t *testing.T){
	t.Log("Starting test")
	t.Log("Initializing user")
	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
	}
	file := userlib.RandomBytes(1000)
	key := string(file)
	t.Log("Storing")
	u.StoreFile(key, file)
	t.Log("Loading")
	out, er := u.LoadFile(key)
	if er != nil {
		t.Error("Error loading file.")
	}
	t.Log("Comparing")
	if !reflect.DeepEqual(file, out) {
		t.Error("Files do not match. Filename: " + key)
	}
	t.Log("Test complete")
}

func TestNonCollison(t *testing.T) {
	//Checks to make sure that two users with same
	//filename don't get each other's files
	t.Log("Initializing users")
	a, err := InitUser("alice", "fubar")
	if (err != nil) || (a == nil) {
		t.Error("Failed to initialize user", err)
	}
	b, er := InitUser("bob", "fubar")
	if (er != nil) || (b == nil) {
		t.Error("Failed to initialize user", err)
	}
	var file_one = []byte("Something creative here")
	var file_two = []byte("Something boring here")
	t.Log("Storing files")
	a.StoreFile("FileName", file_one)
	b.StoreFile("FileName", file_two)
	t.Log("Loading files")
	aFile, err_one := a.LoadFile("FileName")
	if (err_one != nil) {
		t.Error("Error loading file")
	}
	bFile, err_two := b.LoadFile("FileName")
	if (err_two != nil) {
		t.Error("Error loading file")
	}
	t.Log("Checking files")
	if (!reflect.DeepEqual(aFile, file_one)) || (!reflect.DeepEqual(bFile, file_two)) {
		t.Error("Collision has occured; files dont match up with what was put into them.")
	}
	t.Log("Test completed")
}

func TestRandomMalicious(t *testing.T) {
	userlib.DatastoreClear()
	//Randomly modify files we store in our Datastore
	//Verify that we do not return the modified data
	t.Log("Init user")
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	t.Log("Storing key related to user")
	mapper := userlib.DatastoreGetMap()
	var key_store string
	for k, _ := range mapper {
		//Store the key related to the user; do not want to mess with it.
		key_store = k
	}
	t.Log("Storing file")
	u.StoreFile("file", []byte("file"))
	mapper = userlib.DatastoreGetMap()
	t.Log("Initializing attacker intervention.")
	for k, v := range mapper {
		if k != key_store {
			mapper[k] = Shuffler(v)
		}
	}
	t.Log("Loading file")
	out, err_temp := u.LoadFile("file")
	if (err_temp == nil) || (out != nil) {
		t.Error("Should not have been able to load the file.")
	}
	t.Log("Dumping datastore")
	userlib.DatastoreClear()
	t.Log("Test complete")
}

func TestChainSharing(t *testing.T) {
	//Ensure that if a shares with b who then shares with c,
	//c and a have the same file

	t.Log("Init users")
	a, err := InitUser("a", "pass")
	if err != nil {
		t.Error("Failure in init user")
	}
	b, err1 := InitUser("b", "pass")
	if err1 != nil {
		t.Error("Failure in init user")
	}
	c, err2 := InitUser("c", "pass")
	if err2 != nil {
		t.Error("Failure in init user")
	}

	a.StoreFile("test", []byte("This is a testfile."))
	msgid, err3 := a.ShareFile("test", "b")
	if err3 != nil {
		t.Error("Failure in init user")
	}
	b.ReceiveFile("test1", "a", msgid)
	msgid1, err4 := b.ShareFile("test1", "c")
	if err4 != nil {
		t.Error("Failure in init user")
	}
	c.ReceiveFile("test2", "b", msgid1)

	out, err5 := c.LoadFile("test2")
	if err5 != nil {
		t.Error("Failure in init user")
	}
	if string(out) != "This is a testfile." {
		t.Error("Not the same file for whatever reason.")
	}
}

func TestChainSharingRandomMalicious(t *testing.T) {
	userlib.DatastoreClear()
	//If one is maliciously edited, NONE of the files will be opened.

	t.Log("Init users")
	a, err := InitUser("a", "pass")
	if err != nil {
		t.Error("Failure in init user")
	}
	b, err1 := InitUser("b", "pass")
	if err1 != nil {
		t.Error("Failure in init user")
	}
	c, err2 := InitUser("c", "pass")
	if err2 != nil {
		t.Error("Failure in init user")
	}

	//Creating a slice with length 3, enough to store the keys of our users.
	keylist := []string{"a", "b", "c"}
	var counter = 0
	for k, _ := range userlib.DatastoreGetMap() {
		keylist[counter] = k
		counter = counter + 1
	}

	a.StoreFile("test", []byte("This is a testfile."))
	msgid, err3 := a.ShareFile("test", "b")
	if err3 != nil {
		t.Error("Failure in init user")
	}
	b.ReceiveFile("test1", "a", msgid)
	msgid1, err4 := b.ShareFile("test1", "c")
	if err4 != nil {
		t.Error("Failure in init user")
	}
	c.ReceiveFile("test2", "b", msgid1)

	out, err5 := c.LoadFile("test2")
	if err5 != nil {
		t.Error("Failure in init user")
	}
	if string(out) != "This is a testfile." {
		t.Error("Not the same file for whatever reason.")
	}

	t.Log("Messing with map.")

	mapper := userlib.DatastoreGetMap()
	t.Log("Initializing attacker intervention.")
	for k, v := range mapper {
		if !InStringArray(k, keylist) {
			mapper[k] = Shuffler(v)
		}
	}

	out1, err6 := a.LoadFile("file")
	if (err6 == nil) || (out1 != nil) {
		t.Error("Should not have been able to load the file.")
	}
	out2, err7 := a.LoadFile("file")
	if (err7 == nil) || (out2 != nil) {
		t.Error("Should not have been able to load the file.")
	}
	out3, err8 := a.LoadFile("file")
	if (err8 == nil) || (out3 != nil) {
		t.Error("Should not have been able to load the file.")
	}
	userlib.DatastoreClear()
	t.Log("Test complete")
}

func TestAppend(t *testing.T) {
	//The file was changed, but WE are the ones who did it;
	//Will we be able to see the results?
	t.Log("Starting test")
	t.Log("Initializing user")
	u, err := InitUser("alice", "fubar")
	if (err != nil) || (u == nil) {
		t.Error("Failed to initialize user", err)
	}
	t.Log("Storing file")
	var testfile = []byte("will we find this again")
	u.StoreFile("testfile", testfile)
	t.Log("Attempting to load file")
	loadfile, err_one := u.LoadFile("testfile")
	if err_one != nil {
		t.Error("Failed to load our file again")
	}
	if !reflect.DeepEqual(testfile, loadfile) {
		t.Error("Files do not match")
	}
	u.AppendFile("testfile", []byte(" yes, we will!"))
	load1, err2 := u.LoadFile("testfile")
	if err2 != nil {
		t.Error("Failed to load our file again")
	}
	if (string(load1) != "will we find this again yes, we will!") {
		t.Error("Append file failed...")
	}
}

func TestAttackThenAppend(t *testing.T) {
	userlib.DatastoreClear()
	//What happens if we run an attack then append
	//afterwards?
	//Will we get our file back?

	t.Log("Init user")
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	t.Log("Storing key related to user")
	mapper := userlib.DatastoreGetMap()
	var key_store string
	for k, _ := range mapper {
		//Store the key related to the user; do not want to mess with it.
		key_store = k
	}
	t.Log("Storing file")
	u.StoreFile("file", []byte("file"))
	mapper = userlib.DatastoreGetMap()
	t.Log("Initializing attacker intervention.")
	for k, v := range mapper {
		if k != key_store {
			mapper[k] = Shuffler(v)
		}
	}
	u.AppendFile("file", []byte("I CAN TYPE EMBARRASSING THINGS HERE AND NO ONE SHOULD EVER KNOW!"))
	t.Log("Loading file")
	out, err_temp := u.LoadFile("file")
	if (err_temp == nil) || (out != nil) {
		t.Error("Should not have been able to load the file.")
	}
	t.Log("Dumping datastore")
	userlib.DatastoreClear()
	t.Log("Test complete")
}

func TestAttackThenHeavyAppend(t *testing.T) {
	//What if I had a TON of data via numerous appends?
	//Now can I get the data back please?
	userlib.DatastoreClear()
	//What happens if we run an attack then append
	//afterwards?
	//Will we get our file back?

	t.Log("Init user")
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	t.Log("Storing key related to user")
	mapper := userlib.DatastoreGetMap()
	var key_store string
	for k, _ := range mapper {
		//Store the key related to the user; do not want to mess with it.
		key_store = k
	}
	t.Log("Storing file")
	u.StoreFile("file", []byte("file"))
	mapper = userlib.DatastoreGetMap()
	t.Log("Initializing attacker intervention.")
	for k, v := range mapper {
		if k != key_store {
			mapper[k] = Shuffler(v)
		}
	}
	for i:=0; i <10000; i++ {
		u.AppendFile("file", []byte(strconv.Itoa(i)))
	}
	t.Log("Loading file")
	out, err_temp := u.LoadFile("file")
	if (err_temp == nil) || (out != nil) {
		t.Error("Should not have been able to load the file.")
	}
	t.Log("Dumping datastore")
	userlib.DatastoreClear()
	t.Log("Test complete")
}

func TestEnsureEncryption(t *testing.T) {
	//Encryption is generally sanity checked
	//by simply printing out keys and values.
	//This test is designed to mimic this testing regime.

	userlib.DatastoreClear()
	t.Log("Init users")
	a, err := InitUser("a", "pass")
	if (err != nil) || (a == nil) {
		t.Error("Failure in init user")
	}
	a.StoreFile("hi", []byte("Who cares what password I put in here really?"))
	for k, v := range userlib.DatastoreGetMap() {
		println("PLEASE CHECK BY INSPECTION")
		println("Key:")
		println(k)
		println("Value:")
		println(v)
	}
	userlib.DatastoreClear()
	t.Log("Test complete")
}

func TestEmpty(t *testing.T) {
	//If user loads empty file and retrieves it, will a crash occur?

	t.Log("Starting test")
	t.Log("Initializing user")
	u, err := InitUser("alice", "fubar")
	if (err != nil) || (u == nil) {
		t.Error("Failed to initialize user", err)
	}
	t.Log("Storing file")
	var testfile []byte
	u.StoreFile("testfile", testfile)
	t.Log("Attempting to load file")
	loadfile, err_one := u.LoadFile("testfile")
	if err_one != nil {
		t.Error("Failed to load our file again")
	}
	if !reflect.DeepEqual(testfile, loadfile) {
		t.Error("Files do not match")
	}
}

func TestOptimalAppend(t *testing.T) {
	userlib.DatastoreClear()
	userlib.KeystoreClear()
	//Ensure our append function is optimal (faster than adding total info again).
	init := string(userlib.RandomBytes(1000))
	additional := string(userlib.RandomBytes(1000))
	comb := init + additional

	t.Log("Starting test")
	score := 0
	loops := 50
	for i:=0; i <loops; i++ {
		u, err := InitUser("alice", "fubar")
		if (err != nil) || (u == nil) {
			t.Error("Failed to initialize user", err)
		}
		t.Log("Storing file")
		start1 := time.Now()
		u.StoreFile("testfile1", []byte(init))
		u.StoreFile("testfile1", []byte(comb))
		end1 := time.Since(start1)
		start2 := time.Now()
		u.StoreFile("testfile2", []byte(init))
		u.AppendFile("testfile2", []byte(additional))
		end2 := time.Since(start2)
		if (end1 > end2) {
			score = score + 1
		}
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	}
	if (score < 9*loops/10) {
		s := fmt.Sprintf("%f", float64(score)/float64(loops))
		t.Error("Not efficient; worse more than 10% of the time. Score:" + s + "%")
	}
	println(fmt.Sprintf("%f", float64(score)/float64(loops)))
}

func TestRevoke(t *testing.T) {
	//Make sure only the creator can revoke files.

	//Ensure that if a shares with b who then shares with c,
	//c and a have the same file

	t.Log("Init users")
	a, err := InitUser("a", "pass")
	if err != nil {
		t.Error("Failure in init user")
	}
	b, err1 := InitUser("b", "pass")
	if err1 != nil {
		t.Error("Failure in init user")
	}
	c, err2 := InitUser("c", "pass")
	if err2 != nil {
		t.Error("Failure in init user")
	}
	t.Log("Sharing...")
	a.StoreFile("test", []byte("This is a testfile."))
	msgid, err3 := a.ShareFile("test", "b")
	if err3 != nil {
		t.Error("Failure in sharing")
	}
	b.ReceiveFile("test1", "a", msgid)
	msgid1, err4 := b.ShareFile("test1", "c")
	if err4 != nil {
		t.Error("Failure in sharing")
	}
	c.ReceiveFile("test2", "b", msgid1)

	out, err5 := c.LoadFile("test2")
	if err5 != nil {
		t.Error("Failure in sharing")
	}
	if string(out) != "This is a testfile." {
		t.Error("Not the same file for whatever reason.")
	}

	t.Log("Revoking...")
	err6 := a.RevokeFile("test")
	if err6 != nil {
		t.Error("Creator unable to revoke file...", err6)
	}

	t.Log("Verifying success")

	out1, err7 := c.LoadFile("test2")
	if (err7 == nil) || (out1 != nil) {
		t.Error("Still able to load file...")
	}

	out2, err8 := b.LoadFile("test1")
	if (err8 == nil) || (out2 != nil) {
		t.Error("Still able to load file...")
	}

	out3, err9 := a.LoadFile("test")
	if (err9 != nil) || (out3 == nil) {
		t.Error("Revoking revoked access from creator...")
	}
}

func TestLevenshtein(t *testing.T) {
	//If attacker has 2 potential files it sends to server, it cannot determine
	//with probability > 1/2 where the file came from.
	//The Levenshtein Distance is a way of measuring distance between strings.
	//If similar files have smaller distances than different files when in the Datastore,
	//that means they can be distinguished (not good).

	userlib.DatastoreClear()
	userlib.KeystoreClear()

	file1 := []byte("This is file1.")
	file2 := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	file3 := []byte("This is file3.")
	file4 := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYA")

	t.Log("Starting test")
	score := 0
	loops := 50
	for i:=0; i <loops; i++ {
		if i % 2 == 0 {
			u, err := InitUser("alice", "fubar")
			if (err != nil) || (u == nil) {
				t.Error("Failed to initialize user", err)
			}
			keylist := []string{"a", "b", "c"}
			u.StoreFile("file1", file1)
			for k, _ := range userlib.DatastoreGetMap() {
				keylist[0] = k
			}
			u.StoreFile("file2", file2)
			for k, _ := range userlib.DatastoreGetMap() {
				if !InStringArray(k, keylist) {
					keylist[1] = k
				}
			}
			u.StoreFile("file3", file3)
			for k, _ := range userlib.DatastoreGetMap() {
				if !InStringArray(k, keylist) {
					keylist[2] = k
				}
			}
			dist1 := levenshtein.DistanceForStrings([]rune(keylist[0]), []rune([]rune(keylist[2])), levenshtein.DefaultOptions)
			dist2 := levenshtein.DistanceForStrings([]rune(keylist[1]), []rune([]rune(keylist[2])), levenshtein.DefaultOptions)
			if dist1 < dist2 {
				score = score + 1
			}
			userlib.DatastoreClear()
			userlib.KeystoreClear()
		} else {
			u, err := InitUser("alice", "fubar")
			if (err != nil) || (u == nil) {
				t.Error("Failed to initialize user", err)
			}
			keylist := []string{"a", "b", "c"}
			u.StoreFile("file1", file1)
			for k, _ := range userlib.DatastoreGetMap() {
				keylist[0] = k
			}
			u.StoreFile("file2", file2)
			for k, _ := range userlib.DatastoreGetMap() {
				if !InStringArray(k, keylist) {
					keylist[1] = k
				}
			}
			u.StoreFile("file4", file4)
			for k, _ := range userlib.DatastoreGetMap() {
				if !InStringArray(k, keylist) {
					keylist[2] = k
				}
			}
			dist1 := levenshtein.DistanceForStrings([]rune(keylist[0]), []rune([]rune(keylist[2])), levenshtein.DefaultOptions)
			dist2 := levenshtein.DistanceForStrings([]rune(keylist[1]), []rune([]rune(keylist[2])), levenshtein.DefaultOptions)
			if dist1 > dist2 {
				score = score + 1
			}
			userlib.DatastoreClear()
			userlib.KeystoreClear()
		}
	}
	if !((score <= 75*loops/100) && (score >= 25*loops/100)) {
		s := fmt.Sprintf("%f", float64(score)/float64(loops))
		t.Error("Error: Greater than 50% odds at identifying. Score: " + s + "%")
	}
	println(fmt.Sprintf("%f", float64(score)/float64(loops)))
}

func TestRevokeAndUpdate(t *testing.T) {
	//Make sure after a file is revoked, only the person that revoked can edit.

	t.Log("Init users")
	a, err := InitUser("a", "pass")
	if err != nil {
		t.Error("Failure in init user")
	}
	b, err1 := InitUser("b", "pass")
	if err1 != nil {
		t.Error("Failure in init user")
	}
	c, err2 := InitUser("c", "pass")
	if err2 != nil {
		t.Error("Failure in init user")
	}

	a.StoreFile("test", []byte("This is a testfile."))
	msgid, err3 := a.ShareFile("test", "b")
	if err3 != nil {
		t.Error("Failure in sharing")
	}
	b.ReceiveFile("test1", "a", msgid)
	msgid1, err4 := b.ShareFile("test1", "c")
	if err4 != nil {
		t.Error("Failure in sharing")
	}
	c.ReceiveFile("test2", "b", msgid1)

	out, err5 := c.LoadFile("test2")
	if err5 != nil {
		t.Error("Failure in sharing")
	}
	if string(out) != "This is a testfile." {
		t.Error("Not the same file for whatever reason.")
	}

	t.Log("Revoking...")
	err6 := a.RevokeFile("test")
	if err6 != nil {
		t.Error("Creator unable to revoke file...")
	}

	t.Log("Verifying success")

	out1, err7 := c.LoadFile("test2")
	if (err7 == nil) || (out1 != nil) {
		t.Error("Still able to load file...")
	}

	out2, err8 := b.LoadFile("test1")
	if (err8 == nil) || (out2 != nil) {
		t.Error("Still able to load file...")
	}

	out3, err9 := a.LoadFile("test")
	if (err9 != nil) || (out3 == nil) {
		t.Error("Revoking revoked access from creator...")
	}

	err10 := c.AppendFile("test2", []byte("Can't access it eh? Well I will just destroy the file for ya!"))
	if err10 == nil {
		t.Error("Still able to add stuff to the file somehow..")
	}
}

func TestMutateEmpty(t *testing.T) {
	// THE test we failed...(panic as macStart became negative in decryptBlob)
	userlib.DatastoreClear()
	t.Log("Init user")
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	t.Log("Storing key related to user")
	mapper := userlib.DatastoreGetMap()
	var key_store string
	for k, _ := range mapper {
		//Store the key related to the user; do not want to mess with it.
		key_store = k
	}
	t.Log("Storing file")
	u.StoreFile("file", []byte("file"))
	mapper = userlib.DatastoreGetMap()
	t.Log("Initializing attacker intervention.")
	for k, _ := range mapper {
		if k != key_store {
			mapper[k] = []byte("");
		}
	}
	t.Log("Loading file")
	out, err_temp := u.LoadFile("file")
	if (err_temp == nil) || (out != nil) {
		t.Error("Should not have been able to load the file.")
	}
	t.Log("Dumping datastore")
	userlib.DatastoreClear()
	t.Log("Test complete")
}
