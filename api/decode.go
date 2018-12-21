package api

import (
	"encoding/json"
	"fmt"
	"github.com/ugorji/go/codec"
	"net/http"

	b64 "encoding/base64"
	req "github.com/nimblehq/webauthn-growth-demo/request"
)

func JSONResponse(w http.ResponseWriter, d interface{}, c int) {
	dj, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		http.Error(w, "Error creating JSON response", http.StatusInternalServerError)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(c)
	fmt.Fprintf(w, "%s", dj)
}

// UnmarshallClientData - Unmarshall the ClientDataJSON provided by the authenticator.
// It is Base 64 encoded before being sent up to the server, so we b6 decode
// it first.
func UnmarshallClientData(clientData string) (req.DecodedClientData, error) {
	b64Decoder := b64.StdEncoding.Strict()
	clientDataBytes, _ := b64Decoder.DecodeString(clientData)
	var handler codec.Handle = new(codec.JsonHandle)
	var decoder = codec.NewDecoderBytes(clientDataBytes, handler)
	var ucd req.DecodedClientData
	err := decoder.Decode(&ucd)
	ucd.RawClientData = string(clientDataBytes)
	return ucd, err
}
