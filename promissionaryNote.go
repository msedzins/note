package main

import (
	"fmt"

	"crypto/sha256"
	"encoding/base64"
	"encoding/json"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/factory"
	"github.com/hyperledger/fabric/core/chaincode/shim"
	"github.com/hyperledger/fabric/core/chaincode/shim/ext/entities"
	pb "github.com/hyperledger/fabric/protos/peer"
)

type PromissioryNote struct {
	bccspInst bccsp.BCCSP
}

type Transaction struct {
	Signature     string
	EncryptedNote []byte
}

func (t *PromissioryNote) Init(stub shim.ChaincodeStubInterface) pb.Response {

	return shim.Success(nil)
}

func (t *PromissioryNote) Invoke(stub shim.ChaincodeStubInterface) pb.Response {
	fn, args := stub.GetFunctionAndParameters()

	if fn == "new" {

		values, err := stub.GetTransient()
		if err != nil {
			return shim.Error(err.Error())
		} else {

			signature, note, encryptionKeyInBytes, initVectorInBytes, err := extractParametersForNew(stub, values, args)
			if err != nil {
				return shim.Error(err.Error())
			}
			return t.Encrypter(stub, signature, note, encryptionKeyInBytes, initVectorInBytes)
		}
	} else if fn == "query" {

		values, err := stub.GetTransient()
		if err != nil {
			return shim.Error(err.Error())
		} else {

			encryptionKeyInBytes, initVectorInBytes, err := extractParametersForQuery(stub, values)
			if err != nil {
				return shim.Error(err.Error())
			}

			return t.Decrypter(stub, encryptionKeyInBytes, initVectorInBytes)
		}
	}

	return shim.Success(nil)
}

func extractParametersForQuery(stub shim.ChaincodeStubInterface, values map[string][]byte) ([]byte, []byte, error) {

	var err error

	if len(values["encryptionKey"]) == 0 {
		err = fmt.Errorf("Invoke: 'encryptionKey' field empty")
		return nil, nil, err
	}

	if len(values["initVector"]) == 0 {
		err = fmt.Errorf("Invoke: 'initVector' field empty")
		return nil, nil, err
	}

	encryptionKey := base64.StdEncoding.EncodeToString(values["encryptionKey"])
	encryptionKeyInBytes, err := base64.StdEncoding.DecodeString(encryptionKey)
	if err != nil {
		return nil, nil, fmt.Errorf("Converting encryptionKey from base64 failed, err %+v. Key:%s", err, encryptionKey)
	}
	initVector := base64.StdEncoding.EncodeToString(values["initVector"])
	initVectorInBytes, err := base64.StdEncoding.DecodeString(initVector)
	if err != nil {
		return nil, nil, fmt.Errorf("Converting initVector from base64 failed, err %+v. Vector:%s", err, initVector)
	}

	return encryptionKeyInBytes, initVectorInBytes, nil
}

func extractParametersForNew(stub shim.ChaincodeStubInterface, values map[string][]byte, args []string) (string, string, []byte, []byte, error) {

	var err error

	if len(values["note"]) == 0 {
		err = fmt.Errorf("Invoke: 'note' field empty")
		return "", "", nil, nil, err
	}
	if len(values["encryptionKey"]) == 0 {
		err = fmt.Errorf("Invoke: 'encryptionKey' field empty")
		return "", "", nil, nil, err
	}

	if len(values["initVector"]) == 0 {
		err = fmt.Errorf("Invoke: 'initVector' field empty")
		return "", "", nil, nil, err
	}

	if len(args) != 1 {
		err = fmt.Errorf("Invoke: One parameter(signature) required in parameters' list")
		return "", "", nil, nil, err
	}

	signature := args[0]
	tmpNote := base64.StdEncoding.EncodeToString(values["note"])
	note, err := base64.StdEncoding.DecodeString(tmpNote)
	if err != nil {
		return "", "", nil, nil, fmt.Errorf("Converting note from base64 failed, err %+v. Key:%s", err, tmpNote)
	}

	encryptionKey := base64.StdEncoding.EncodeToString(values["encryptionKey"])
	encryptionKeyInBytes, err := base64.StdEncoding.DecodeString(encryptionKey)
	if err != nil {
		return "", "", nil, nil, fmt.Errorf("Converting encryptionKey from base64 failed, err %+v. Key:%s", err, encryptionKey)
	}
	initVector := base64.StdEncoding.EncodeToString(values["initVector"])
	initVectorInBytes, err := base64.StdEncoding.DecodeString(initVector)
	if err != nil {
		return "", "", nil, nil, fmt.Errorf("Converting initVector from base64 failed, err %+v. Vector:%s", err, initVector)
	}

	return signature, string(note), encryptionKeyInBytes, initVectorInBytes, nil
}

func (t *PromissioryNote) Decrypter(stub shim.ChaincodeStubInterface, encKey, IV []byte) pb.Response {
	// create the encrypter entity - we give it an ID, the bccsp instance, the key and (optionally) the IV
	ent, err := entities.NewAES256EncrypterEntity("ID", t.bccspInst, encKey, IV)
	if err != nil {
		return shim.Error(fmt.Sprintf("entities.NewAES256EncrypterEntity failed, err %s", err))
	}

	hash := sha256.New()
	hash.Write(encKey)
	key := base64.StdEncoding.EncodeToString(hash.Sum(nil))

	var transactionInBytes []byte
	transactionInBytes, err = stub.GetState(key)
	if err != nil {
		return shim.Error(fmt.Sprintf("GetState failed, err %+v", err))
	}
	if len(transactionInBytes) == 0 {
		return shim.Error(fmt.Sprintf("Note not found! Key:%s", key))
	}

	transaction := Transaction{}
	err = json.Unmarshal(transactionInBytes, &transaction)
	if err != nil {
		return shim.Error(fmt.Sprintf("Unmarshaling failed, err %+v", err))
	}

	decryptedNote, err := ent.Decrypt(transaction.EncryptedNote)
	if err != nil {
		return shim.Error(fmt.Sprintf("Decrypting of the note failed, err %+v", err))
	}

	type DecryptedTransaction struct {
		Signature     string
		DecryptedNote string
	}
	decryptedTransaction := DecryptedTransaction{Signature: transaction.Signature,
		DecryptedNote: string(decryptedNote)}
	transactionInBytes, err = json.Marshal(decryptedTransaction)
	if err != nil {
		return shim.Error(fmt.Sprintf("Marshaling of DecryptedTransaction failed, err %+v", err))
	}

	return shim.Success(transactionInBytes)
}

// Encrypter writes state to the ledger after having
// encrypted it with an AES 256 bit key that has been provided to the chaincode through the
// transient field
func (t *PromissioryNote) Encrypter(stub shim.ChaincodeStubInterface, signature string, note string, encKey, IV []byte) pb.Response {
	// create the encrypter entity - we give it an ID, the bccsp instance, the key and (optionally) the IV
	ent, err := entities.NewAES256EncrypterEntity("ID", t.bccspInst, encKey, IV)
	if err != nil {
		return shim.Error(fmt.Sprintf("entities.NewAES256EncrypterEntity failed, err %s", err))
	}

	hash := sha256.New()
	hash.Write(encKey)
	key := base64.StdEncoding.EncodeToString(hash.Sum(nil))

	transaction := Transaction{}
	transaction.EncryptedNote, err = ent.Encrypt([]byte(note))
	if err != nil {
		return shim.Error(fmt.Sprintf("encryption failed, err %+v", err))
	}
	transaction.Signature = signature
	transactionInBytes, err := json.Marshal(transaction)

	if err != nil {
		return shim.Error(fmt.Sprintf("Marshaling transaction structure failed, err %+v. ", err))
	}

	err = stub.PutState(key, transactionInBytes)
	if err != nil {
		return shim.Error(fmt.Sprintf("PutState failed, err %+v", err))
	}
	return shim.Success([]byte(key))
}

func (t *PromissioryNote) InitializeBCCSP() {

	factory.InitFactories(nil)
	t.bccspInst = factory.GetDefault()
}

func main() {
	note := new(PromissioryNote)
	note.InitializeBCCSP()

	err := shim.Start(note)
	if err != nil {
		fmt.Printf("Error starting PromissioryNote chaincode: %s", err)
	}
}
