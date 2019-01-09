package main

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/hyperledger/fabric/bccsp/factory"
	"github.com/hyperledger/fabric/core/chaincode/shim"
	"github.com/hyperledger/fabric/core/chaincode/shim/ext/entities"
	"github.com/stretchr/testify/require"
)

func TestInvokeAbsenceOfNoteIsHandledWithError(t *testing.T) {

	//Given
	testStub := CustomMockStub{}
	args := [][]byte{
		[]byte("new"), []byte("key1"),
		[]byte("value1")}
	testStub.SetTransient(map[string]string{
		"encryptionKey": "6BJVZR1nq6hPiOHCVTtziRd4eusri+I46kJp4gkwZ3c="})

	//When
	result := testStub.MockInvokeWithTransient(new(PromissioryNote), args)

	//Then
	if result.Message != "Invoke: 'note' field empty" {
		t.Errorf("Invoke  didn't return expected error. Return status: %d. Error returned: %s",
			result.Status, result.Message)
	}
}

func TestInvokeAbsenceOfEncryptionKeyIsHandledWithError(t *testing.T) {

	//Given
	testStub := CustomMockStub{}
	args := [][]byte{
		[]byte("new"), []byte("key1"),
		[]byte("value1")}
	testStub.SetTransient(map[string]string{
		"note": "note1"})

	//When
	result := testStub.MockInvokeWithTransient(new(PromissioryNote), args)

	//Then
	if result.Message != "Invoke: 'encryptionKey' field empty" {
		t.Errorf("Invoke  didn't return expected error. Return status: %d. Error returned: %s",
			result.Status, result.Message)
	}
}

func TestInvokeAbsenceOfInitVectorIsHandledWithError(t *testing.T) {

	//Given
	testStub := CustomMockStub{}
	args := [][]byte{
		[]byte("new"), []byte("key1"),
		[]byte("value1")}
	testStub.SetTransient(map[string]string{
		"note":          "note1",
		"encryptionKey": "encryptionKey1"})

	//When
	result := testStub.MockInvokeWithTransient(new(PromissioryNote), args)

	//Then
	if result.Message != "Invoke: 'initVector' field empty" {
		t.Errorf("Invoke  didn't return expected error. Return status: %d. Error returned: %s",
			result.Status, result.Message)
	}
}

func TestInvokeNotEnoughParametersIsHandledWithError(t *testing.T) {

	//Given
	testStub := CustomMockStub{}
	args := [][]byte{[]byte("new")}
	testStub.SetTransient(map[string]string{
		"note":          "note1",
		"initVector":    "initVector",
		"encryptionKey": "encryptionKey1"})

	//When
	result := testStub.MockInvokeWithTransient(new(PromissioryNote), args)

	//Then
	if result.Message != "Invoke: One parameter(signature) required in parameters' list" {
		t.Errorf("Invoke  didn't return expected error. Return status: %d. Error returned: %s",
			result.Status, result.Message)
	}
}

func TestCreationOfNewNote(t *testing.T) {

	//Given
	testStub := CustomMockStub{}
	encryptionKey := "6BJVZR1nq6hPiOHCVTtziRd4eusri+I46kJp4gkwZ3c="
	initVector := "S8A6cJlm5u5Hul458M72yw=="
	noteXML := "PHhtbD50aGlzIGlzIGFuIGV4YW1wbGFyeSBub3RlPC94bWw+" //"<xml>this is an examplary note</xml>"
	signature := "example of signature"

	args := [][]byte{
		[]byte("new"), []byte(signature)}
	testStub.SetTransient(map[string]string{
		"encryptionKey": encryptionKey,
		"initVector":    initVector,
		"note":          noteXML,
	})

	note := new(PromissioryNote)
	note.InitializeBCCSP()

	//When
	result := testStub.MockInvokeWithTransient(note, args)

	//Then
	require.Equal(t, "", result.Message)

	value, error := testStub.GetState(string(result.Payload))
	require.Empty(t, error)

	var transaction Transaction
	error = json.Unmarshal(value, &transaction)
	require.Empty(t, error)
	require.Equal(t, signature, transaction.Signature) //check first field extracted from Ladger

	factory.InitFactories(nil)
	bccsp := factory.GetDefault()
	encryptionKeyInBytes, error := base64.StdEncoding.DecodeString(encryptionKey)
	require.Empty(t, error)
	initVectorInBytes, error := base64.StdEncoding.DecodeString(initVector)
	require.Empty(t, error)
	ent, error := entities.NewAES256EncrypterEntity("ID", bccsp, []byte(encryptionKeyInBytes), []byte(initVectorInBytes))
	require.Empty(t, error)

	decryptedValue, error := ent.Decrypt(transaction.EncryptedNote)
	require.Empty(t, error)
	require.Equal(t, "<xml>this is an examplary note</xml>", string(decryptedValue)) // check second field extracted from Ladger
}

func TestQueryOfNote(t *testing.T) {

	//Given
	testStub := CustomMockStub{}
	encryptionKey := "6BJVZR1nq6hPiOHCVTtziRd4eusri+I46kJp4gkwZ3c="
	initVector := "S8A6cJlm5u5Hul458M72yw=="
	noteXML := "PHhtbD50aGlzIGlzIGFuIGV4YW1wbGFyeSBub3RlPC94bWw+" //"<xml>this is an examplary note</xml>"
	signature := "example of signature"

	args := [][]byte{
		[]byte("new"), []byte(signature)}
	testStub.SetTransient(map[string]string{
		"encryptionKey": encryptionKey,
		"initVector":    initVector,
		"note":          noteXML})

	note := new(PromissioryNote)
	note.InitializeBCCSP()
	originalStub := shim.NewMockStub("mockChaincodeStub", note)
	result := testStub.MockInvokeWithTransientAndStub(note, args, originalStub)
	require.Equal(t, "", result.Message)

	//When
	args = [][]byte{
		[]byte("query")}
	testStub.SetTransient(map[string]string{
		"encryptionKey": encryptionKey,
		"initVector":    initVector})
	result = testStub.MockInvokeWithTransientAndStub(note, args, originalStub)
	require.Equal(t, "", result.Message)

	//Then
	type DecryptedTransaction struct {
		Signature     string
		DecryptedNote string
	}
	var transaction DecryptedTransaction
	error := json.Unmarshal(result.Payload, &transaction)
	require.Empty(t, error)
	require.Equal(t, signature, transaction.Signature)                                  //check first field extracted from Ladger
	require.Equal(t, "<xml>this is an examplary note</xml>", transaction.DecryptedNote) // check second field extracted from Ladger
}
