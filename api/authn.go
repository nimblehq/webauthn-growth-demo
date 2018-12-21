package api

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/duo-labs/webauthn/config"
	"github.com/duo-labs/webauthn/models"
	"github.com/ugorji/go/codec"
	"math/big"
	"net/url"
	"strings"

	b64 "encoding/base64"
	req "github.com/nimblehq/webauthn-growth-demo/request"
)

func DecodeAttestationObject(rawAttObj string) (req.EncodedAuthData, error) {
	b64Decoder := b64.URLEncoding.Strict()
	attObjBytes, err := b64Decoder.DecodeString(rawAttObj)
	if err != nil {
		fmt.Println("b64 Decode error:", err)
		return req.EncodedAuthData{}, err
	}
	var handler codec.Handle = new(codec.CborHandle)
	var decoder = codec.NewDecoderBytes(attObjBytes, handler)
	var ead req.EncodedAuthData
	err = decoder.Decode(&ead)
	if err != nil {
		fmt.Println("CBOR Decode error:", err)
		return req.EncodedAuthData{}, err
	}
	return ead, err
}

// ParseAuthData - Parses the AuthData returned from the authenticator from a byte array
func ParseAuthData(ead req.EncodedAuthData) (req.DecodedAuthData, error) {
	decodedAuthData := req.DecodedAuthData{}

	rpID := ead.AuthData[:32]
	rpIDHash := hex.EncodeToString(rpID)

	intFlags := ead.AuthData[32]
	flags := fmt.Sprintf("%08b", intFlags)

	counter := ead.AuthData[33:38]

	if len(ead.AuthData) < 38 {
		err := errors.New("AuthData byte array is not long enough")
		return decodedAuthData, err
	}

	aaguid := ead.AuthData[38:54]

	credIDLen := ead.AuthData[53] + ead.AuthData[54]

	credID := ead.AuthData[55 : 55+credIDLen]

	cborPubKey := ead.AuthData[55+credIDLen:]

	var handler codec.Handle = new(codec.CborHandle)
	decoder := codec.NewDecoderBytes(cborPubKey, handler)

	var pubKey models.PublicKey
	err := decoder.Decode(&pubKey)
	if err != nil {
		fmt.Println("Error decoding the Public Key in Authentication Data")
		return decodedAuthData, err
	}

	decodedAuthData = req.DecodedAuthData{
		// Flags are used to determine user presence, user verification, and if attData is present
		Flags: []byte(flags),
		// Counter is used to prevent replay attacks
		Counter: counter,
		// RPIDHash is used to verify the Auth Request
		RPIDHash: rpIDHash,
		// AAGUID is the ID of the Authenticator device line
		AAGUID: aaguid,
		// CredID is the ID of the credential we are creating
		CredID: credID,
		// Public Key of the credential key pair
		PubKey: pubKey,
		// Format of the attestation statement (ex, "u2f", "safety-net"), currently defaults to "none"
		Format: ead.Format,
	}

	// If the format is one that contains an authenticator attestation certificate then parse it
	if ead.Format == "fido-u2f" {
		das, err := ParseAttestationStatement(ead.AttStatement)
		if err != nil {
			fmt.Println("Error parsing Attestation Statement from Authentication Data")
			return decodedAuthData, err
		}
		// The authenticator's attestation statement
		decodedAuthData.AttStatement = das
	}

	return decodedAuthData, err
}

// ParseAssertionData - Parses assertion data from byte array to a struct
func ParseAssertionData(assertionData []byte, hexSig string) (req.DecodedAssertionData, error) {
	decodedAssertionData := req.DecodedAssertionData{}

	rpID := assertionData[:32]
	rpIDHash := hex.EncodeToString(rpID)

	intFlags := assertionData[32]

	counter := assertionData[33:]

	if len(assertionData) > 38 {
		err := errors.New("assertionData byte array is too long")
		return decodedAssertionData, err
	}

	rawSig, err := hex.DecodeString(hexSig)
	if err != nil {
		return decodedAssertionData, err
	}

	decodedAssertionData = req.DecodedAssertionData{
		Flags:            intFlags,
		RPIDHash:         rpIDHash,
		Counter:          counter,
		RawAssertionData: assertionData,
		Signature:        rawSig,
	}

	return decodedAssertionData, err
}

// ParseAttestationStatement - parse the Attestation Certificate returned by the
// the authenticator
func ParseAttestationStatement(
	ead req.EncodedAttestationStatement) (req.DecodedAttestationStatement, error) {
	das := req.DecodedAttestationStatement{}
	// Currently, for fido-u2f formatted attStatements, we only support one x509 cert
	// but it is returned to us as an array
	cert, err := x509.ParseCertificate(ead.X509Cert[0])
	if err != nil {
		return das, err
	}
	das = req.DecodedAttestationStatement{
		Certificate: cert,
		Signature:   ead.Signature,
	}
	return das, nil
}

// VerifyAssertionData - Verifies that the Assertion data provided is correct and valid
func VerifyAssertionData(
	clientData *req.DecodedClientData,
	authData *req.DecodedAssertionData,
	sessionData *models.SessionData,
	credentialID string) (bool, models.Credential, error) {
	// Step 1. Using credential’s id attribute (or the corresponding rawId,
	// if base64url encoding is inappropriate for your use case), look up the
	// corresponding credential public key.

	fmt.Printf("Auth data is %+v\n", authData)

	// var credential models.Credential
	credential, err := models.GetCredentialForUser(&sessionData.User, credentialID)
	if err != nil {
		fmt.Println("Issue getting credential during Assertion")
		err := errors.New("Issue getting credential during Assertion")
		return false, credential, err
	}

	// Step 2. Let cData, aData and sig denote the value of credential’s
	// response's clientDataJSON, authenticatorData, and signature respectively.

	// Okeydoke

	// Step 3. Perform JSON deserialization on cData to extract the client data
	// C used for the signature.

	// Already done above

	fmt.Printf("Decoded Client Data: %+v\n", clientData)
	fmt.Printf("Auth Data: %+v\n", authData)

	credential.Counter = authData.Counter
	err = CheckCredentialCounter(&credential)
	if err != nil {
		fmt.Println("Error updating the the counter")
		err := errors.New("Error updating the the counter")
		return false, credential, err
	}

	// Step 4. Verify that the type in C is the string webauthn.create
	if clientData.ActionType != "webauthn.get" {
		fmt.Println("Client Request type is: ", string(clientData.ActionType))
		err := errors.New("The webauthn action type is incorrect")
		return false, credential, err
	}

	// Step 5. Verify that the challenge member of C matches the challenge that
	// was sent to the authenticator in the PublicKeyCredentialRequestOptions
	// passed to the get() call.
	sessionDataChallenge := strings.Trim(b64.URLEncoding.EncodeToString(sessionData.Challenge), "=")
	if sessionDataChallenge != clientData.Challenge {
		fmt.Println("Stored Challenge is: ", string(sessionDataChallenge))
		fmt.Println("Client Challenge is: ", string(clientData.Challenge))
		err := errors.New("Stored and Given Sessions do not match")
		return false, credential, err
	}

	// Step 6. Verify that the origin member of C matches the Relying Party's origin.
	cdo, err := url.Parse(clientData.Origin)
	if err != nil {
		fmt.Println("Error Parsing Client Data Origin: ", string(clientData.Origin))
		err := errors.New("Error Parsing the Client Data Origin")
		return false, credential, err
	}

	if sessionData.RelyingPartyID != cdo.Hostname() {
		fmt.Println("Stored Origin is: ", string(sessionData.RelyingPartyID))
		fmt.Println("Client Origin is: ", string(clientData.Origin))
		err := errors.New("Stored and Client Origin do not match")
		return false, credential, err
	}

	// Step 7. Verify that the tokenBindingId member of C (if present) matches the
	// Token Binding ID for the TLS connection over which the signature was obtained.

	// No Token Binding ID exists in this example. Sorry bruv

	// Step 8. Verify that the clientExtensions member of C is a subset of the extensions
	// requested by the Relying Party and that the authenticatorExtensions in C is also a
	// subset of the extensions requested by the Relying Party.

	// We don't have any clientExtensions

	// Step 9. Verify that the RP ID hash in aData is the SHA-256 hash of the RP ID expected
	// by the Relying Party.
	hasher := sha256.New()
	hasher.Write([]byte(config.Conf.HostAddress)) // We use our default RP ID - Host
	RPIDHash := hasher.Sum(nil)
	hexRPIDHash := hex.EncodeToString(RPIDHash)
	if hexRPIDHash != (authData.RPIDHash) {
		fmt.Println("Stored RP Hash is: ", hexRPIDHash)
		fmt.Println("Client RP Hash is: ", string(authData.RPIDHash))
		err := errors.New("Stored and Client RP ID Hash do not match")
		return false, credential, err
	}

	// Step 10. Let hash be the result of computing a hash over the cData using the
	// algorithm represented by the hashAlgorithm member of C.

	var clientDataHash []byte
	switch clientData.HashAlgorithm {
	case "SHA-512":
		h := sha512.New()
		h.Write([]byte(clientData.RawClientData))
		clientDataHash = h.Sum(nil)
		fmt.Printf("Client data hash is %x\n", clientDataHash)
	case "SHA-256":
		h := sha256.New()
		h.Write([]byte(clientData.RawClientData))
		clientDataHash = h.Sum(nil)
		fmt.Printf("Client data hash is %x\n", clientDataHash)
	default:
		// Currently, the Editor's Draft makes no mention of hashAlgorithm
		// in the client data, but we can default to SHA256.
		h := sha256.New()
		h.Write([]byte(clientData.RawClientData))
		clientDataHash = h.Sum(nil)
		fmt.Printf("Client data hash is %x\n", clientDataHash)
	}

	// Step 11. Using the credential public key looked up in step 1, verify that sig
	// is a valid signature over the binary concatenation of aData and hash.
	binCat := append(authData.RawAssertionData, clientDataHash...)

	pubKey, err := models.GetPublicKeyForCredential(&credential)
	if err != nil {
		fmt.Println("Error retreiving Public Key for Credential")
		err := errors.New("Error retrieving public key for credential")
		return false, credential, err
	}

	var ecsdaSig struct {
		R, S *big.Int
	}

	sig := authData.Signature
	_, err = asn1.Unmarshal(sig, &ecsdaSig)
	if err != nil {
		return false, credential, errors.New("Error unmarshalling signature")
	}

	h := sha256.New()
	h.Write(binCat)

	return ecdsa.Verify(&pubKey, h.Sum(nil), ecsdaSig.R, ecsdaSig.S), credential, nil
}

// CheckCredentialCounter - We may want to check for replay attacks but
// we definitely want to update the internal counter
// Note: this currently doesn't do that, LOL
func CheckCredentialCounter(cred *models.Credential) error {
	return models.UpdateCredential(cred)
}
