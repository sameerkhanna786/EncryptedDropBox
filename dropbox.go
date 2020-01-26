package proj2

import (
	"helpers"
	"encoding/json"
	"encoding/hex"
	"github.com/google/uuid"
	"strings"
	"errors"
)

// This serves two purposes: It shows you some useful primitives and
// it suppresses warnings for items not being imported
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	helpers.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	helpers.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	helpers.DebugMsg("The hex: %v", h)

	// TESTING ENCRYPT+MAC
	/*
	Conclusion:
	1. define ciphertext to be same length as plaintext and XORKeyStream into it
	2. Then append IV to beginning
	3. To do MAC, if you wanna add something to the ciphertext, hex.EncodeToString that thing and append
	4. MAC length is 32 bytes
	5. Append MAC to end of ciphertext
	6. On decryption, repeat the exact same process to calculate MAC
	7. Length of finale should be = len(ciphertext) - 32 - helpers.BlockSize
	*/
	plaintext := []byte("Mary had a little lamb")
	iv := helpers.RandomBytes(helpers.BlockSize)
	kay := helpers.RandomBytes(helpers.AESKeySize)
	encrypter := helpers.CFBEncrypter(kay, iv)
	ciphertext := make([]byte, len(plaintext))
	encrypter.XORKeyStream(ciphertext, plaintext)
	ciphertext = append(iv, ciphertext...)

	chkString := "holy"
	confUser := helpers.NewHMAC(kay)
	confUser.Write([]byte(chkString))
	confUserBytes := []byte(hex.EncodeToString(confUser.Sum([]byte(""))))

	maac := helpers.NewHMAC(kay)
	maac.Write(append(ciphertext, confUserBytes...))
	maacBytes := maac.Sum([]byte(""))
	ciphertext = append(ciphertext, maacBytes...)
	helpers.DebugMsg("maac: %x", maacBytes)

	chkIV := ciphertext[:helpers.BlockSize]
	chkmac := ciphertext[len(ciphertext)-32:]
	rest := ciphertext[:len(ciphertext)-32]

	mach := helpers.NewHMAC(kay)
	mach.Write(append(rest, confUserBytes...))
	machBytes := mach.Sum([]byte(""))
	flag := helpers.Equal(machBytes, chkmac)
	helpers.DebugMsg("mach: %x", machBytes)
	helpers.DebugMsg("chkk: %x", chkmac)
	if (!flag) {
		helpers.DebugMsg("%s", "integrity lost")
	}

	decrypter := helpers.CFBDecrypter(kay, chkIV)
	finale := make([]byte, len(ciphertext)-32-helpers.BlockSize)
	decrypter.XORKeyStream(finale, ciphertext[helpers.BlockSize:len(ciphertext)-32])
	helpers.DebugMsg("Decrypted string: %s", string(finale))

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	helpers.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	helpers.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	helpers.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var key *helpers.PrivateKey
	key, _ = helpers.GenerateRSAKey()
	helpers.DebugMsg("Key is %v", key)
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

type FileInfo struct {
	FileIDs []uuid.UUID
	EncryptionKey []byte
	MacKey []byte
}

// The structure definition for a user record
type User struct {
	Username string
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
	Privat helpers.PrivateKey
	EncryptionKey []byte
	MacKey []byte
	FilenameKey []byte
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored
// User data: the name used in the datastore should not be guessable
// without also knowing the password and username.

func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User

	// using password and salt (username) to generate keys for storing user info
	argon := helpers.Argon2Key([]byte(password), []byte(username), uint32(3*helpers.AESKeySize))
	userNameKey := argon[:helpers.AESKeySize]
	encryptKey := argon[helpers.AESKeySize:2*helpers.AESKeySize]
	macKey := argon[2*helpers.AESKeySize:]

	// HMAC over username
	confUser := helpers.NewHMAC(userNameKey)
	confUser.Write([]byte(username))
	confUserBytes := []byte(hex.EncodeToString(confUser.Sum([]byte(""))))

	// User Keys Generation
	var RSAKeyPair *helpers.PrivateKey
	RSAKeyPair, err = helpers.GenerateRSAKey()
	if err != nil {
		return nil, err
	}

	userdata.Username = username
	userdata.Privat = *RSAKeyPair
	userdata.EncryptionKey = helpers.RandomBytes(helpers.AESKeySize)
	userdata.MacKey = helpers.RandomBytes(helpers.AESKeySize)
	userdata.FilenameKey = helpers.RandomBytes(helpers.AESKeySize)
	user, _ := json.Marshal(userdata)
	userCipher := encryptBlob(user, encryptKey, macKey, confUserBytes)

	// putting in stores
	helpers.DatastoreSet(hex.EncodeToString(confUser.Sum([]byte(""))), userCipher)
	helpers.KeystoreSet(username, RSAKeyPair.PublicKey)
	return &userdata, nil
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User

	// using password and salt (username) to generate keys for storing user info
	argon := helpers.Argon2Key([]byte(password), []byte(username), uint32(3*helpers.AESKeySize))
	userNameKey := argon[:helpers.AESKeySize]
	encryptKey := argon[helpers.AESKeySize:2*helpers.AESKeySize]
	macKey := argon[2*helpers.AESKeySize:]

	// HMAC over username
	confUser := helpers.NewHMAC(userNameKey)
	confUser.Write([]byte(username))
	confUserBytes := []byte(hex.EncodeToString(confUser.Sum([]byte(""))))

	userCipher, ok := helpers.DatastoreGet(hex.EncodeToString(confUser.Sum([]byte(""))))
	if !ok {
		return nil, errors.New("User not found or incorrect username/password")
	}
	stuff, err := decryptBlob(userCipher, encryptKey, macKey, confUserBytes)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(stuff, &userdata)
	if err != nil {
		return nil, err
	}
	return &userdata, nil
}

// This stores a file in the datastore.
//
// The name of the file should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {

	confFile := helpers.NewHMAC(userdata.FilenameKey)
	confFile.Write([]byte(userdata.Username + filename))
	confFileString := hex.EncodeToString(confFile.Sum([]byte("")))
	macStuff := []byte(hex.EncodeToString([]byte(userdata.Username + filename)))

	encryptedDataNode, ok := helpers.DatastoreGet(confFileString)
	if !ok {
		helpers.DatastoreSet(confFileString, userdata.storeUtility(filename, data, nil))
	} else {
		node, err := decryptBlob(encryptedDataNode, userdata.EncryptionKey, userdata.MacKey, macStuff)
		if err != nil {
			helpers.DatastoreSet(confFileString, userdata.storeUtility(filename, data, nil))
			return
		}
		helpers.DatastoreSet(confFileString, userdata.storeUtility(filename, data, node))
	}
}

// This adds on to an existing file.
func (userdata *User) AppendFile(filename string, data []byte) (err error) {

	rawDataNode, err := userdata.loadDataNode(filename)
	if err != nil {
		return err
	}
	var dataNode DataNode
	err = json.Unmarshal(rawDataNode, &dataNode)
	if err != nil {
		return err
	}
	dataNodeIDBytes, _ := json.Marshal(dataNode.ID)

	// fetching FileInfo
	encryptedStuff, ok := helpers.DatastoreGet(dataNode.ID.String())
	if !ok {
		return errors.New("Fileinfo not found")
	}
	IDBytes, _ := json.Marshal(dataNode.ID)
	stuff, err := decryptBlob(encryptedStuff, dataNode.EncryptionKey, dataNode.MacKey, IDBytes)
	if err != nil {
		return err
	}

	var info FileInfo
	err = json.Unmarshal(stuff, &info)
	if err != nil {
		return err
	}

	id := uuid.New()
	idBytes, _ := json.Marshal(id)
	info.FileIDs = append(info.FileIDs, id)
	infoBytes, _ := json.Marshal(info)

	helpers.DatastoreSet(id.String(), encryptBlob(data, info.EncryptionKey, info.MacKey, idBytes))
	helpers.DatastoreSet(dataNode.ID.String(), encryptBlob(infoBytes, dataNode.EncryptionKey, dataNode.MacKey, dataNodeIDBytes))

	return nil
}

// This loads a file from the Datastore.
//
// Gives an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {

	rawDataNode, err := userdata.loadDataNode(filename)
	if err != nil {
		return nil, err
	}
	var dataNode DataNode
	err = json.Unmarshal(rawDataNode, &dataNode)
	if err != nil {
		return nil, err
	}

	// fetching FileInfo
	encryptedStuff, ok := helpers.DatastoreGet(dataNode.ID.String())
	if !ok {
		return nil, errors.New("Fileinfo not found")
	}
	IDBytes, _ := json.Marshal(dataNode.ID)
	stuff, err := decryptBlob(encryptedStuff, dataNode.EncryptionKey, dataNode.MacKey, IDBytes)
	if err != nil {
		return nil, err
	}

	var info FileInfo
	err = json.Unmarshal(stuff, &info)
	if err != nil {
		return nil, err
	}

	var ans []byte
	for _, v := range info.FileIDs {
		file, ok := helpers.DatastoreGet(v.String())
		if !ok {
			return nil, errors.New("File not found")
		}
		idBytes, _ := json.Marshal(v)
		raw, err := decryptBlob(file, info.EncryptionKey, info.MacKey, idBytes)
		if err != nil {
			return nil, err
		}
		ans = append(ans, raw...)
	}
	return ans, nil
}

type DataNode struct {
	ID uuid.UUID
	EncryptionKey []byte
	MacKey []byte
}
// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.

func (userdata *User) ShareFile(filename string, recipient string) (
	msgid string, err error) {

	key, ok := helpers.KeystoreGet(recipient)
	if !ok {
		return "", errors.New("Recipient not found")
	}
	rawDataNode, err := userdata.loadDataNode(filename)
	if err != nil {
		return "", err
	}
	var dataNode DataNode
	err = json.Unmarshal(rawDataNode, &dataNode)
	if err != nil {
		return "", err
	}

	tag, _ := json.Marshal(userdata.Privat.PublicKey)
	ciphertext, err := helpers.RSAEncrypt(&key, rawDataNode, tag)
	if err != nil {
		return "", err
	}
	sign, err := helpers.RSASign(&userdata.Privat, ciphertext)
	if err != nil {
		return "", err
	}
	ciphertext = append(sign, ciphertext...)
	return hex.EncodeToString(ciphertext), nil
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	msgid string) error {

	senderKey, ok := helpers.KeystoreGet(sender)
	if !ok {
		return errors.New("Sender not found")
	}
	ciphertext, err := hex.DecodeString(msgid)
	if err != nil {
		return err
	}

	toDecrypt := ciphertext[256:]
	sign := make([]byte, 256)
	copy(sign, ciphertext[:256])

	err = helpers.RSAVerify(&senderKey, toDecrypt, sign)
	if err != nil {
		return err
	}
	tag, _ := json.Marshal(senderKey)
	decrypted, err := helpers.RSADecrypt(&userdata.Privat, toDecrypt, tag)
	if err != nil {
		return err
	}

	var dataNode DataNode
	err = json.Unmarshal(decrypted, &dataNode)
	if err != nil {
		return err
	}
	confFile := helpers.NewHMAC(userdata.FilenameKey)
	confFile.Write([]byte(userdata.Username + filename))
	confFileString := hex.EncodeToString(confFile.Sum([]byte("")))
	macStuff := []byte(hex.EncodeToString([]byte(userdata.Username + filename)))

	helpers.DatastoreSet(confFileString, encryptBlob(decrypted, userdata.EncryptionKey, userdata.MacKey, macStuff))
	return nil
}

// Removes access for all others.
func (userdata *User) RevokeFile(filename string) (err error) {

	loadedFile, err := userdata.LoadFile(filename)
	if err != nil {
		return err
	}
	rawDataNode, err := userdata.loadDataNode(filename)
	if err != nil {
		return err
	}
	var dataNode DataNode
	err = json.Unmarshal(rawDataNode, &dataNode)
	if err != nil {
		return err
	}

	// fetching FileInfo
	encryptedStuff, ok := helpers.DatastoreGet(dataNode.ID.String())
	if !ok {
		return errors.New("Fileinfo not found")
	}
	helpers.DatastoreDelete(dataNode.ID.String()) // Revoking DataNode access

	IDBytes, _ := json.Marshal(dataNode.ID)
	stuff, err := decryptBlob(encryptedStuff, dataNode.EncryptionKey, dataNode.MacKey, IDBytes)
	if err != nil {
		var info FileInfo
		err = json.Unmarshal(stuff, &info)
		if err != nil {
			for _, v := range info.FileIDs {
				helpers.DatastoreDelete(v.String()) // Removing file data
			}
		}
	}

	confFile := helpers.NewHMAC(userdata.FilenameKey)
	confFile.Write([]byte(userdata.Username + filename))
	confFileString := hex.EncodeToString(confFile.Sum([]byte("")))
	helpers.DatastoreSet(confFileString, userdata.storeUtility(filename, loadedFile, nil))

	return nil
}

func (userdata *User) storeUtility(filename string, data []byte, node []byte) []byte {
	var dataNode DataNode
	if node != nil {
		err := json.Unmarshal(node, &dataNode)
		if err != nil {
			dataNode.ID = uuid.New()
			dataNode.EncryptionKey = helpers.RandomBytes(helpers.AESKeySize)
			dataNode.MacKey = helpers.RandomBytes(helpers.AESKeySize)
		}
	} else {
		dataNode.ID = uuid.New()
		dataNode.EncryptionKey = helpers.RandomBytes(helpers.AESKeySize)
		dataNode.MacKey = helpers.RandomBytes(helpers.AESKeySize)
	}
	dataNodeBytes, _ := json.Marshal(dataNode)
	dataNodeIDBytes, _ := json.Marshal(dataNode.ID)

	fileID := uuid.New()
	fileIDBytes, _ := json.Marshal(fileID)

	var info FileInfo
	info.FileIDs = []uuid.UUID{fileID}
	info.EncryptionKey = helpers.RandomBytes(helpers.AESKeySize)
	info.MacKey = helpers.RandomBytes(helpers.AESKeySize)
	infoBytes, _ := json.Marshal(info)

	helpers.DatastoreSet(fileID.String(), encryptBlob(data, info.EncryptionKey, info.MacKey, fileIDBytes))

	infoCipher := encryptBlob(infoBytes, dataNode.EncryptionKey, dataNode.MacKey, dataNodeIDBytes)
	helpers.DatastoreSet(dataNode.ID.String(), infoCipher)

	macStuff := []byte(hex.EncodeToString([]byte(userdata.Username + filename)))
	return encryptBlob(dataNodeBytes, userdata.EncryptionKey, userdata.MacKey, macStuff)
}

func (userdata *User) loadDataNode(filename string) ([]byte, error) {

	confFile := helpers.NewHMAC(userdata.FilenameKey)
	confFile.Write([]byte(userdata.Username + filename))
	confFileString := hex.EncodeToString(confFile.Sum([]byte("")))
	macStuff := []byte(hex.EncodeToString([]byte(userdata.Username + filename)))

	// fetching DataNode
	encryptedDataNode, ok := helpers.DatastoreGet(confFileString)
	if !ok {
		return nil, errors.New("Datanode not found")
	}
	rawDataNode, err := decryptBlob(encryptedDataNode, userdata.EncryptionKey, userdata.MacKey, macStuff)
	if err != nil {
		return nil, err
	}
	return rawDataNode, nil
}

func encryptBlob(plaintext []byte, encryptKey []byte, macKey []byte, macStuff []byte) (data []byte) {
	iv := helpers.RandomBytes(helpers.BlockSize)
	encrypter := helpers.CFBEncrypter(encryptKey, iv)
	ciphertext := make([]byte, len(plaintext))
	encrypter.XORKeyStream(ciphertext, plaintext)
	ciphertext = append(iv, ciphertext...)

	mac := helpers.NewHMAC(macKey)
	mac.Write(append(ciphertext, macStuff...))
	ciphertext = append(ciphertext, mac.Sum([]byte(""))...)
	return ciphertext
}

func decryptBlob(ciphertext []byte, encryptKey []byte, macKey []byte, macStuff []byte) (data []byte, err error) {
	macStart := len(ciphertext)-32
	if macStart <= 0 {
		return nil, errors.New("Integrity lost")
	}
	checkMac := make([]byte, 32)
	copy(checkMac, ciphertext[macStart:])
	rest := ciphertext[:macStart]

	mac := helpers.NewHMAC(macKey)
	mac.Write(append(rest, macStuff...))
	if !helpers.Equal(checkMac, mac.Sum([]byte(""))) {
		return nil, errors.New("Integrity lost")
	}
	iv := ciphertext[:helpers.BlockSize]
	toDecrypt := ciphertext[helpers.BlockSize:macStart]
	decrypter := helpers.CFBDecrypter(encryptKey, iv)
	stuff := make([]byte, len(toDecrypt))
	decrypter.XORKeyStream(stuff, toDecrypt)
	return stuff, nil
}
