package api

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/duo-labs/webauthn/config"
	"github.com/duo-labs/webauthn/models"
	"math/big"
	"net/url"
	"strings"

	b64 "encoding/base64"
	req "github.com/nimblehq/webauthn-growth-demo/request"
)

// VerifyRegistrationData - Verify that the provided Authenticator and Client
func VerifyRegistrationData(
	clientData *req.DecodedClientData,
	authData *req.DecodedAuthData,
	sessionData *models.SessionData) (bool, error) {

	fmt.Printf("Decoded Client Data: %+v\n", clientData)
	fmt.Printf("Auth Data: %+v\n", authData)

	// As per the spec we have already deserialized the
	// Auth Attestation Response and have extracted the client data (called C)
	// So step 1 is done, we have C

	// Step 2. Verify that the type in C is the string webauthn.create
	if clientData.ActionType != "webauthn.create" {
		fmt.Println("Client Request type is: ", string(clientData.ActionType))
		err := errors.New("The webauthn action type is incorrect")
		return false, err
	}

	// Step 3. Verify that the challenge in C matches the challenge
	// that was sent to the authenticator in the create() call.
	// C.challenge is returned without padding, so we trim our padding
	sessionDataChallenge := strings.Trim(b64.URLEncoding.EncodeToString(sessionData.Challenge), "=")
	if sessionDataChallenge != clientData.Challenge {
		fmt.Println("Stored Challenge is: ", string(sessionDataChallenge))
		fmt.Println("Client Challenge is: ", string(clientData.Challenge))
		err := errors.New("Stored and Given Sessions do not match")
		return false, err
	}

	// Step 4. Verify that to origin in C matches the relying party's origin
	cdo, err := url.Parse(clientData.Origin)
	if err != nil {
		fmt.Println("Error Parsing Client Data Origin: ", string(clientData.Origin))
		err := errors.New("Error Parsing the Client Data Origin")
		return false, err
	}

	if sessionData.RelyingPartyID != cdo.Hostname() {
		fmt.Println("Stored Origin is: ", string(sessionData.RelyingPartyID))
		fmt.Println("Client Origin is: ", string(clientData.Origin))
		err := errors.New("Stored and Client Origin do not match")
		return false, err
	}

	// Step 5. Verify that the tokenBindingID in C matches for the TLS connection
	// over which we handled this ceremony

	// we don't have this yet 'cus no TLS is necessary for local dev!

	// Step 6. Verify that the clientExtensions in C is a subset of the extensions
	// requested by the RP and that the authenticatorExtensions in C is also a
	// subset of the extensions requested by the RP.

	// We have no extensions yet!

	// Step 7. Compute the hash of clientDataJSON using the algorithm identified
	// by C.hashAlgorithm.
	// Let's also make sure that the Authenticator is using SHA-256 or SHA-512
	var clientDataHash []byte
	fmt.Println("Hash Alg:", clientData.HashAlgorithm)
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

	// Step 8. Perform CBOR decoding on the attestationObject field of
	// the AuthenticatorAttestationResponse structure to obtain the
	// attestation statement format fmt, the authenticator data authData,
	// and the attestation statement attStmt.

	// We've already done this an put it in authData

	// Step 9. Verify that the RP ID hash in authData is indeed the
	// SHA-256 hash of the RP ID expected by the RP.
	hasher := sha256.New()
	hasher.Write([]byte(config.Conf.HostAddress)) // We use our default RP ID - Host
	RPIDHash := hasher.Sum(nil)
	computedRPIDHash := hex.EncodeToString(RPIDHash)
	if string(computedRPIDHash) != (authData.RPIDHash) {
		fmt.Println("Stored RP Hash is: ", string(computedRPIDHash))
		fmt.Println("Client RP Hash is: ", string(authData.RPIDHash))
		err := errors.New("Stored and Client RP ID Hash do not match")
		return false, err
	}

	// Step 10. Determine the attestation statement format by performing
	// an USASCII case-sensitive match on fmt against the set of supported
	// WebAuthn Attestation Statement Format Identifier values.

	if authData.Format != "none" && authData.Format != "fido2-u2f" && authData.Format != "packed" {
		fmt.Println("Auth Data Format is incorrect:", authData.Format)
		err := errors.New("Auth data is not in proper format")
		return false, err
	}

	isValid := false

	if authData.Format == "fido-u2f" {
		// Step 11. Verify that attStmt is a correct, validly-signed attestation
		// statement, using the attestation statement format fmt’s verification
		// procedure given authenticator data authData and the hash of the
		// serialized client data computed in step 6.

		// We start using FIDO U2F Specs here

		// If clientDataHash is 256 bits long, set tbsHash to this value.
		// Otherwise set tbsHash to the SHA-256 hash of clientDataHash.
		var tbsHash []byte
		if len(clientDataHash) == 32 {
			tbsHash = clientDataHash
		} else {
			hasher = sha256.New()
			hasher.Write(clientDataHash)
			tbsHash = hasher.Sum(nil)
		}

		// From authenticatorData, extract the claimed RP ID hash, the
		// claimed credential ID and the claimed credential public key.
		RPIDHash, err = hex.DecodeString(authData.RPIDHash)
		if err != nil {
			err := errors.New("Error decoding RPIDHash")
			return false, err
		}

		pubKey := authData.AttStatement.Certificate.PublicKey.(*ecdsa.PublicKey)
		fmt.Printf("Public Key from Certificate: %+v\n", authData.AttStatement.Certificate.PublicKey)
		fmt.Printf("Public Key from Auth Data: %+v\n", authData.PubKey)

		// We already have the claimed credential ID and PubKey

		assembledData, err := AssembleSignedRegistrationData(RPIDHash, tbsHash, authData.CredID, authData.PubKey)
		if err != nil {
			fmt.Println(err)
			return false, err
		}

		var ecsdaSig struct {
			R, S *big.Int
		}

		sig := authData.AttStatement.Signature

		_, err = asn1.Unmarshal(sig, &ecsdaSig)
		fmt.Printf("ECDSA SIG: %+v\n", ecsdaSig)
		if err != nil {
			return false, errors.New("Error unmarshalling signature")
		}

		h := sha256.New()
		h.Write(assembledData)
		isValid = ecdsa.Verify(pubKey, h.Sum(nil), ecsdaSig.R, ecsdaSig.S)
	} else {
		isValid = true
	}

	// Verification of attestation objects requires that the Relying Party has a trusted
	// method of determining acceptable trust anchors in step 11 above. Also, if certificates
	// are being used, the Relying Party must have access to certificate status information for
	// the intermediate CA certificates. The Relying Party must also be able to build the
	// attestation certificate chain if the client did not provide this chain in the attestation
	// information.

	// To avoid ambiguity during authentication, the Relying Party SHOULD check that
	// each credential is registered to no more than one user. If registration is
	// requested for a credential that is already registered to a different user, the
	// Relying Party SHOULD fail this ceremony, or it MAY decide to accept the registration,
	// e.g. while deleting the older registration.

	return isValid, err
}

func AssembleSignedRegistrationData(
	rpIDHash,
	tbsHash,
	credID []byte,
	pubKey models.PublicKey,
) ([]byte, error) {
	buf := bytes.NewBuffer([]byte{0x00})
	buf.Write(rpIDHash)
	buf.Write(tbsHash)
	buf.Write(credID)
	buf.WriteByte(0x04)
	buf.Write(pubKey.XCoord)
	buf.Write(pubKey.YCoord)
	return buf.Bytes(), nil
}
