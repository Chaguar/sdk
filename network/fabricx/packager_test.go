/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package fabricx

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-protos-go-apiv2/peer"
	"github.com/hyperledger/fabric-x-common/api/applicationpb"
	"github.com/hyperledger/fabric-x-common/protoutil"
	sdk "github.com/hyperledger/fabric-x-sdk"
	"github.com/hyperledger/fabric-x-sdk/blocks"
	bfabx "github.com/hyperledger/fabric-x-sdk/blocks/fabricx"
	"github.com/hyperledger/fabric-x-sdk/endorsement"
	efab "github.com/hyperledger/fabric-x-sdk/endorsement/fabric"
	efabx "github.com/hyperledger/fabric-x-sdk/endorsement/fabricx"
	"github.com/hyperledger/fabric-x-sdk/identity"
	nfab "github.com/hyperledger/fabric-x-sdk/network/fabric"
	"google.golang.org/protobuf/proto"
)

// newMSPSigner writes a self-signed ECDSA identity to a temporary MSP folder in
// the layout identity.SignerFromMSP reads, and loads it. It returns the signer
// exactly as production code builds one, along with the certificate PEM.
func newMSPSigner(t *testing.T, mspID string) (identity.Signer, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "user@" + mspID, Organization: []string{mspID}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	dir := t.TempDir()
	for name, content := range map[string][]byte{
		filepath.Join("keystore", "priv_sk"):   pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		filepath.Join("signcerts", "cert.pem"): certPEM,
	} {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	s, err := identity.SignerFromMSP(dir, mspID)
	if err != nil {
		t.Fatalf("SignerFromMSP: %v", err)
	}
	return s, certPEM
}

// newEndorsement returns a proposal created by client and a response from a
// different org's endorser, which is what CreateTx packages.
func newEndorsement(t *testing.T, client sdk.Signer) sdk.Endorsement {
	t.Helper()
	endorser, _ := newMSPSigner(t, "Org2MSP")

	inv, err := efabx.NewInvocationBuilder(client).NewInvocation("mychannel", "myns", "v1", 3, [][]byte{[]byte("fn")})
	if err != nil {
		t.Fatalf("NewInvocation: %v", err)
	}
	res := endorsement.Success(blocks.ReadWriteSet{
		Writes: []blocks.KVWrite{{Key: "a", Value: []byte("va")}},
	}, "", nil, nil)
	resp, err := efabx.NewEndorsementBuilder(endorser).Endorse(inv, res)
	if err != nil {
		t.Fatalf("Endorse: %v", err)
	}
	return sdk.Endorsement{Proposal: inv.Proposal, Responses: []*peer.ProposalResponse{resp}}
}

// unpack returns the payload and its signature header from an envelope.
func unpack(t *testing.T, env *common.Envelope) (*common.Payload, *common.SignatureHeader) {
	t.Helper()
	payl, err := protoutil.UnmarshalPayload(env.Payload)
	if err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	shdr, err := protoutil.UnmarshalSignatureHeader(payl.Header.SignatureHeader)
	if err != nil {
		t.Fatalf("unmarshal signature header: %v", err)
	}
	return payl, shdr
}

// verifyEnvelope does what an orderer enforcing a Writers policy does: read the
// creator as an msppb.Identity, and check the envelope signature over the
// payload bytes against the certificate it carries. It does not evaluate a
// policy, so it does not check the certificate against an MSP's CA.
func verifyEnvelope(env *common.Envelope) error {
	payl, err := protoutil.UnmarshalPayload(env.Payload)
	if err != nil {
		return err
	}
	shdr, err := protoutil.UnmarshalSignatureHeader(payl.Header.SignatureHeader)
	if err != nil {
		return err
	}
	id, err := protoutil.UnmarshalIdentity(shdr.Creator)
	if err != nil {
		return err
	}
	cert, err := parseCert(id.GetCertificate())
	if err != nil {
		return err
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("creator certificate is not an ECDSA certificate")
	}
	digest := sha256.Sum256(env.Payload)
	if !ecdsa.VerifyASN1(pub, digest[:], env.Signature) {
		return errors.New("signature does not verify over the payload")
	}
	return nil
}

func parseCert(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, errors.New("creator is not a PEM certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

// TestCreateTx_Signed checks the wire format the router's signature filter
// reads: the creator must parse as an msppb.Identity, although the SDK's
// signers serialize an msp.SerializedIdentity, and the signature must verify
// over the payload bytes.
func TestCreateTx_Signed(t *testing.T) {
	client, certPEM := newMSPSigner(t, "Org1MSP")
	end := newEndorsement(t, client)

	env, err := CreateTx(end.Proposal, client, end.Responses...)
	if err != nil {
		t.Fatalf("CreateTx: %v", err)
	}

	payl, shdr := unpack(t, env)
	id, err := protoutil.UnmarshalIdentity(shdr.Creator)
	if err != nil {
		t.Fatalf("creator does not parse as msppb.Identity: %v", err)
	}
	if id.MspId != "Org1MSP" {
		t.Errorf("unexpected MSP ID: %q", id.MspId)
	}
	if !bytes.Equal(id.GetCertificate(), certPEM) {
		t.Error("creator does not carry the signer's certificate")
	}
	if len(env.Signature) == 0 {
		t.Fatal("expected a signature")
	}
	if err := verifyEnvelope(env); err != nil {
		t.Errorf("envelope does not verify: %v", err)
	}

	// signing must not change what is being submitted
	chdr, err := protoutil.UnmarshalChannelHeader(payl.Header.ChannelHeader)
	if err != nil {
		t.Fatalf("unmarshal channel header: %v", err)
	}
	if common.HeaderType(chdr.Type) != common.HeaderType_MESSAGE {
		t.Errorf("unexpected header type: %s", common.HeaderType(chdr.Type))
	}
	unsigned, err := CreateTx(end.Proposal, nil, end.Responses...)
	if err != nil {
		t.Fatalf("CreateTx: %v", err)
	}
	unsignedPayl, _ := unpack(t, unsigned)
	if !bytes.Equal(payl.Data, unsignedPayl.Data) {
		t.Error("signed and unsigned envelopes carry different transactions")
	}
}

// TestCreateTx_TamperedPayload guards verifyEnvelope itself, and with it
// the claim that the signature is over the payload bytes and not something else.
func TestCreateTx_TamperedPayload(t *testing.T) {
	client, _ := newMSPSigner(t, "Org1MSP")
	end := newEndorsement(t, client)

	env, err := CreateTx(end.Proposal, client, end.Responses...)
	if err != nil {
		t.Fatalf("CreateTx: %v", err)
	}
	if err := verifyEnvelope(env); err != nil {
		t.Fatalf("untampered envelope does not verify: %v", err)
	}

	payl, _ := unpack(t, env)
	payl.Data = append(payl.Data, 0x00)
	env.Payload = protoutil.MarshalOrPanic(payl)
	if err := verifyEnvelope(env); err == nil {
		t.Error("tampered payload must not verify")
	}
}

// checkOrdererStructure mirrors the structure check fabric-x-orderer (v1.0.9+, #1330) runs on
// every request in SigFilter.requestToSignedData, whether or not it verifies client signatures:
// a non-empty nonce, TxId == ComputeTxID(nonce, creator), and a creator that parses as an
// msppb.Identity. The SDK's integration test cannot catch a violation, because the committer
// test node's mock orderer accepts any envelope.
func checkOrdererStructure(env *common.Envelope) error {
	payl, err := protoutil.UnmarshalPayload(env.Payload)
	if err != nil {
		return err
	}
	if payl.Header == nil || payl.Header.SignatureHeader == nil || payl.Header.ChannelHeader == nil {
		return errors.New("missing header")
	}
	shdr, err := protoutil.UnmarshalSignatureHeader(payl.Header.SignatureHeader)
	if err != nil {
		return err
	}
	chdr, err := protoutil.UnmarshalChannelHeader(payl.Header.ChannelHeader)
	if err != nil {
		return err
	}
	if len(shdr.GetNonce()) == 0 {
		return errors.New("missing nonce in signature header")
	}
	if err := protoutil.CheckTxID(chdr.GetTxId(), shdr.GetNonce(), shdr.GetCreator()); err != nil {
		return err
	}
	_, err = protoutil.UnmarshalIdentity(shdr.Creator)
	return err
}

// TestCreateTx_OrdererStructure: every envelope the SDK builds must pass the orderer's
// structure check, signed or not, for local invocations and remote-endorser proposals alike.
func TestCreateTx_OrdererStructure(t *testing.T) {
	client, _ := newMSPSigner(t, "Org1MSP")
	endorser, _ := newMSPSigner(t, "Org2MSP")
	local := newEndorsement(t, client)

	signedProp, err := nfab.NewSignedProposal(client, "mychannel", "myns", [][]byte{[]byte("fn")})
	if err != nil {
		t.Fatalf("NewSignedProposal: %v", err)
	}
	inv, err := efab.Parse(signedProp, time.Now())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	resp, err := efabx.NewEndorsementBuilder(endorser).Endorse(inv, endorsement.Success(blocks.ReadWriteSet{
		Writes: []blocks.KVWrite{{Key: "a", Value: []byte("va")}},
	}, "", nil, nil))
	if err != nil {
		t.Fatalf("Endorse: %v", err)
	}
	remote := sdk.Endorsement{Proposal: inv.Proposal, Responses: []*peer.ProposalResponse{resp}}
	anonymous := newEndorsement(t, nil)

	for name, create := range map[string]func() (*common.Envelope, error){
		"local signed":      func() (*common.Envelope, error) { return NewTxPackager(client).PackageTx(local) },
		"local unsigned":    func() (*common.Envelope, error) { return NewTxPackager(nil).PackageTx(local) },
		"anonymous":         func() (*common.Envelope, error) { return NewTxPackager(nil).PackageTx(anonymous) },
		"zero TxPackager":   func() (*common.Envelope, error) { return TxPackager{}.PackageTx(local) },
		"remote signed":     func() (*common.Envelope, error) { return NewTxPackager(client).PackageTx(remote) },
		"remote unsigned":   func() (*common.Envelope, error) { return NewTxPackager(nil).PackageTx(remote) },
		"CreateTx unsigned": func() (*common.Envelope, error) { return CreateTx(local.Proposal, nil, local.Responses...) },
	} {
		t.Run(name, func(t *testing.T) {
			env, err := create()
			if err != nil {
				t.Fatalf("create: %v", err)
			}
			if err := checkOrdererStructure(env); err != nil {
				t.Errorf("orderer would reject the envelope: %v", err)
			}
		})
	}
}

// TestCreateTx_Unsigned pins the unsigned shape: no signature, and the proposal's
// signature header carried over unchanged, since the TxID is derived from it.
func TestCreateTx_Unsigned(t *testing.T) {
	client, _ := newMSPSigner(t, "Org1MSP")
	end := newEndorsement(t, client)

	env, err := NewTxPackager(nil).PackageTx(end)
	if err != nil {
		t.Fatalf("PackageTx: %v", err)
	}
	if len(env.Signature) != 0 {
		t.Errorf("expected no signature, got %d bytes", len(env.Signature))
	}
	payl, _ := unpack(t, env)
	hdr, err := protoutil.UnmarshalHeader(end.Proposal.Header)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payl.Header.SignatureHeader, hdr.SignatureHeader) {
		t.Error("envelope signature header differs from the proposal's")
	}
}

// TestCreateTx_SignerNotCreator: the orderer verifies the signature against the creator
// in the header, so another identity's signature would be rejected there; fail early.
func TestCreateTx_SignerNotCreator(t *testing.T) {
	client, _ := newMSPSigner(t, "Org1MSP")
	other, _ := newMSPSigner(t, "Org1MSP")
	end := newEndorsement(t, client)

	if _, err := CreateTx(end.Proposal, other, end.Responses...); err == nil || !strings.Contains(err.Error(), "not the creator") {
		t.Errorf("expected a creator mismatch error, got %v", err)
	}
}

// TestCreateTx_SignedAnonymous: an anonymous invocation has no creator to verify a
// signature against, so it can only be packaged unsigned.
func TestCreateTx_SignedAnonymous(t *testing.T) {
	client, _ := newMSPSigner(t, "Org1MSP")
	end := newEndorsement(t, nil)

	if _, err := CreateTx(end.Proposal, client, end.Responses...); err == nil || !strings.Contains(err.Error(), "not the creator") {
		t.Errorf("expected a creator mismatch error, got %v", err)
	}
}

// TestCreateTx_MalformedProposal: a proposal whose TxID does not derive from its
// signature header would be rejected by the orderer after Submit returned nil.
func TestCreateTx_MalformedProposal(t *testing.T) {
	client, _ := newMSPSigner(t, "Org1MSP")
	end := newEndorsement(t, client)

	withShdr := func(shdr *common.SignatureHeader) *peer.Proposal {
		hdr, err := protoutil.UnmarshalHeader(end.Proposal.Header)
		if err != nil {
			t.Fatal(err)
		}
		hdr.SignatureHeader = protoutil.MarshalOrPanic(shdr)
		return &peer.Proposal{Header: protoutil.MarshalOrPanic(hdr), Payload: end.Proposal.Payload}
	}
	hdr, err := protoutil.UnmarshalHeader(end.Proposal.Header)
	if err != nil {
		t.Fatal(err)
	}
	orig, err := protoutil.UnmarshalSignatureHeader(hdr.SignatureHeader)
	if err != nil {
		t.Fatal(err)
	}

	for name, tc := range map[string]struct {
		shdr *common.SignatureHeader
		want string
	}{
		"empty header":  {&common.SignatureHeader{}, "no nonce"},
		"other nonce":   {&common.SignatureHeader{Nonce: []byte("other"), Creator: orig.Creator}, "does not match"},
		"other creator": {&common.SignatureHeader{Nonce: orig.Nonce, Creator: []byte("other")}, "does not match"},
	} {
		t.Run(name, func(t *testing.T) {
			for _, signer := range []sdk.Signer{nil, client} {
				_, err := CreateTx(withShdr(tc.shdr), signer, end.Responses...)
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Errorf("signer %v: expected %q error, got %v", signer != nil, tc.want, err)
				}
			}
		})
	}
}

func TestPackageTx_Signed(t *testing.T) {
	client, _ := newMSPSigner(t, "Org1MSP")
	end := newEndorsement(t, client)

	env, err := NewTxPackager(client).PackageTx(end)
	if err != nil {
		t.Fatalf("PackageTx: %v", err)
	}
	if err := verifyEnvelope(env); err != nil {
		t.Errorf("envelope does not verify: %v", err)
	}
}

// TestCreateTx_RemoteEndorserProposal: a client sends remote endorsers a Fabric
// SignedProposal, which fabric.Parse only accepts as an ENDORSER_TRANSACTION.
// The packaged envelope must still be a MESSAGE, or Fabric-X ignores it.
func TestCreateTx_RemoteEndorserProposal(t *testing.T) {
	client, _ := newMSPSigner(t, "Org1MSP")
	endorser, _ := newMSPSigner(t, "Org2MSP")

	signedProp, err := nfab.NewSignedProposal(client, "mychannel", "myns", [][]byte{[]byte("fn")})
	if err != nil {
		t.Fatalf("NewSignedProposal: %v", err)
	}
	inv, err := efab.Parse(signedProp, time.Now())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	res := endorsement.Success(blocks.ReadWriteSet{
		Writes: []blocks.KVWrite{{Key: "a", Value: []byte("va")}},
	}, "", nil, nil)
	resp, err := efabx.NewEndorsementBuilder(endorser).Endorse(inv, res)
	if err != nil {
		t.Fatalf("Endorse: %v", err)
	}

	env, err := CreateTx(inv.Proposal, client, resp)
	if err != nil {
		t.Fatalf("CreateTx: %v", err)
	}
	tx, err := bfabx.NewBlockParser(sdk.NoOpLogger{}).ParseTx(env)
	if err != nil {
		t.Fatalf("ParseTx: %v", err)
	}
	if tx == nil {
		t.Fatal("the Fabric-X parser skipped the transaction")
	}
	if tx.ID != inv.TxID {
		t.Errorf("tx id %q, want %q", tx.ID, inv.TxID)
	}
}

// brokenSigner has the client's identity, but cannot sign.
type brokenSigner struct{ sdk.Signer }

func (brokenSigner) Sign([]byte) ([]byte, error) { return nil, errors.New("hsm unavailable") }

type noIdentitySigner struct{}

func (noIdentitySigner) Sign([]byte) ([]byte, error) { return []byte("sig"), nil }
func (noIdentitySigner) Serialize() ([]byte, error)  { return nil, errors.New("no identity") }

// TestCreateTx_SignerErrors: signer.Serialize() builds the envelope's own creator now, so a
// serialize failure surfaces here just as much as a sign failure does.
func TestCreateTx_SignerErrors(t *testing.T) {
	client, _ := newMSPSigner(t, "Org1MSP")
	end := newEndorsement(t, client)

	if _, err := CreateTx(end.Proposal, brokenSigner{client}, end.Responses...); err == nil || !strings.Contains(err.Error(), "hsm unavailable") {
		t.Errorf("expected the signing error, got %v", err)
	}
	if _, err := CreateTx(end.Proposal, noIdentitySigner{}, end.Responses...); err == nil || !strings.Contains(err.Error(), "no identity") {
		t.Errorf("expected the serialize error, got %v", err)
	}
}

// TestCreateTx_NeedsResponses keeps the input validation of CreateTx on
// the signed path too.
func TestCreateTx_NeedsResponses(t *testing.T) {
	client, _ := newMSPSigner(t, "Org1MSP")
	end := newEndorsement(t, client)

	if _, err := CreateTx(end.Proposal, client); err == nil {
		t.Error("expected an error without proposal responses")
	}
}

func TestPackageTx_CertificateIDEndorsement(t *testing.T) {
	client, clientCert := newMSPSigner(t, "Org1MSP")
	endorser, endorserCert := newMSPSigner(t, "Org2MSP")
	const certificateID = "registered-endorser-ID"
	compact, err := endorser.WithCertificateID(certificateID)
	if err != nil {
		t.Fatal(err)
	}
	hashed, err := endorser.WithCertificateHash()
	if err != nil {
		t.Fatal(err)
	}
	certBlock, _ := pem.Decode(endorserCert)
	certDigest := sha256.Sum256(certBlock.Bytes)
	wantIDs := []string{"", certificateID, hex.EncodeToString(certDigest[:])}
	inv, err := efabx.NewInvocationBuilder(client).NewInvocation("mychannel", "myns", "v1", 3, nil)
	if err != nil {
		t.Fatal(err)
	}
	var responses []*peer.ProposalResponse
	for _, signer := range []sdk.Signer{endorser, compact, hashed} {
		resp, err := efabx.NewEndorsementBuilder(signer).Endorse(inv, endorsement.Success(blocks.ReadWriteSet{
			Writes: []blocks.KVWrite{{Key: "a", Value: []byte("va")}},
		}, "", nil, nil))
		if err != nil {
			t.Fatal(err)
		}
		responses = append(responses, resp)
	}
	env, err := NewTxPackager(client).PackageTx(sdk.Endorsement{Proposal: inv.Proposal, Responses: responses})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyEnvelope(env); err != nil {
		t.Fatal(err)
	}
	payl, shdr := unpack(t, env)
	creator, err := protoutil.UnmarshalIdentity(shdr.Creator)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(creator.GetCertificate(), clientCert) || creator.GetMspId() != "Org1MSP" {
		t.Fatal("client's full-certificate identity changed")
	}
	var tx applicationpb.Tx
	if err := proto.Unmarshal(payl.Data, &tx); err != nil {
		t.Fatal(err)
	}
	if len(tx.Namespaces) != 1 || len(tx.Endorsements) != 1 || len(tx.Endorsements[0].EndorsementsWithIdentity) != 3 {
		t.Fatalf("unexpected packaged transaction: %v", &tx)
	}
	cert, err := parseCert(endorserCert)
	if err != nil {
		t.Fatal(err)
	}
	message, err := tx.Namespaces[0].ASN1Marshal(inv.TxID, tx.Metadata)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(message)
	for i, endorsement := range tx.Endorsements[0].EndorsementsWithIdentity {
		id := endorsement.Identity
		if id.GetMspId() != "Org2MSP" || !bytes.Equal(endorsement.Endorsement, responses[i].Endorsement.Signature) {
			t.Fatal("endorser MSP ID or signature changed during packaging")
		}
		if i == 0 {
			if !bytes.Equal(id.GetCertificate(), endorserCert) || id.GetCertificateId() != "" {
				t.Fatal("full-certificate endorsement changed")
			}
		} else if id.GetCertificateId() != wantIDs[i] || len(id.GetCertificate()) != 0 {
			t.Fatal("certificate ID was not preserved")
		}
		if !ecdsa.VerifyASN1(cert.PublicKey.(*ecdsa.PublicKey), digest[:], endorsement.Endorsement) {
			t.Fatal("packaged endorsement signature does not verify")
		}
	}
}
