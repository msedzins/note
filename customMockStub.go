package main

import (
	"encoding/base64"

	"github.com/hyperledger/fabric/core/chaincode/shim"
	pb "github.com/hyperledger/fabric/protos/peer"
)

type CustomMockStub struct {
	shim.MockStub

	args      [][]byte
	transient map[string][]byte
}

func (stub *CustomMockStub) GetTransient() (map[string][]byte, error) {

	return stub.transient, nil
}

func (stub *CustomMockStub) SetTransient(transient map[string]string) {

	stub.transient = map[string][]byte{}

	for index, element := range transient {
		stub.transient[index], _ = base64.StdEncoding.DecodeString(element)
	}

}

// Replacement of the original MockStub.MockInvoke with added support for GetTransient
func (stub *CustomMockStub) MockInvokeWithTransient(note *PromissioryNote, args [][]byte) pb.Response {
	stub.MockStub = *shim.NewMockStub("mockChaincodeStub", note)

	stub.args = args
	stub.MockTransactionStart("test")
	res := note.Invoke(stub)
	stub.MockTransactionEnd("test")

	return res
}

func (stub *CustomMockStub) MockInvokeWithTransientAndStub(note *PromissioryNote, args [][]byte, existingStub *shim.MockStub) pb.Response {
	stub.MockStub = *existingStub

	stub.args = args
	stub.MockTransactionStart("test")
	res := note.Invoke(stub)
	stub.MockTransactionEnd("test")

	return res
}

//Below methods are copy-paste from mockstub.go (MockStub original code)
//Unfortunately it needs to be done so that we are able to set "args" in MockInvokeWithTransient
//To set "args" we need to override GetArgs only but as there  is no polymorphism in Golang we need to
//override all other methods below as well (otherwise for example: original GetStringArgs will call original GetArgs (not the new one)

func (stub *CustomMockStub) GetArgs() [][]byte {
	return stub.args
}

func (stub *CustomMockStub) GetStringArgs() []string {
	args := stub.GetArgs()
	strargs := make([]string, 0, len(args))
	for _, barg := range args {
		strargs = append(strargs, string(barg))
	}
	return strargs
}

func (stub *CustomMockStub) GetFunctionAndParameters() (function string, params []string) {
	allargs := stub.GetStringArgs()
	function = ""
	params = []string{}
	if len(allargs) >= 1 {
		function = allargs[0]
		params = allargs[1:]
	}
	return
}
