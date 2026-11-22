/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package fabricx

import (
	"bytes"
	"context"
	b64 "encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-protos-go-apiv2/peer"
	"github.com/hyperledger/fabric-x-common/api/applicationpb"
	"github.com/hyperledger/fabric-x-common/api/msppb"
	"github.com/hyperledger/fabric-x-common/protoutil"
	sdk "github.com/hyperledger/fabric-x-sdk"
	"github.com/hyperledger/fabric-x-sdk/network"
	"google.golang.org/protobuf/proto"
)

// NewTxPackager returns a TxPackager that assembles Fabric-X transaction envelopes.
//
// Signer is only required if the orderer enforces the channel Writers policy on submitted requests
// (fabric-x-orderer: General.ClientSignatureVerificationRequired). The SDK cannot detect that
// setting: an unsigned envelope sent to such an orderer is rejected by the router only after Submit
// has already returned nil. If set, the signer must be the identity that built the invocation, as the
// orderer checks the signature against the creator the TxID was derived from.
//
// Either way, the envelope carries the invocation's nonce and creator, because the orderer requires
// TxID == SHA256(nonce‖creator) on every request. With a nil signer the envelope carries no signature,
// so nothing proves who submitted it: the creator is then only input to the TxID, and the nonce only
// makes the TxID unique. An invocation built without a signer (fabricx.NewInvocationBuilder(nil))
// has an empty creator, so the envelope carries no identity at all; it can only be packaged unsigned.
func NewTxPackager(signer sdk.Signer) TxPackager {
	return TxPackager{signer: signer}
}

// TxPackager assembles a Fabric-X transaction envelope from an endorsement, signed by the
// submitting client if it has a signer. The zero value packages unsigned envelopes.
type TxPackager struct {
	signer sdk.Signer
}

// PackageTx combines the proposal and endorser responses into a Fabric-X envelope, signed if the
// packager has a signer (General.ClientSignatureVerificationRequired=true on the orderer).
func (p TxPackager) PackageTx(end sdk.Endorsement) (*common.Envelope, error) {
	return CreateTx(end.Proposal, p.signer, end.Responses...)
}

// CreateTx is an adaptation of protoutil.CreateSignedTx, tweaked to work with Fabric-X payloads.
// It assembles an envelope from proposal and resps, signed by signer if it is not nil.
// The envelope reuses the proposal's signature header, so its nonce and creator match the TxID
// the endorsers signed. A non-nil signer must serialize to that creator.
//
// The proposal may come from fabricx.InvocationBuilder or be a Fabric SignedProposal
// that remote endorsers parsed with fabric.Parse; either way the envelope is a
// Fabric-X MESSAGE transaction.
func CreateTx(proposal *peer.Proposal, signer sdk.Signer, resps ...*peer.ProposalResponse) (*common.Envelope, error) {
	if len(resps) == 0 {
		return nil, errors.New("at least one proposal response is required")
	}

	// ensure that all actions are bitwise equal and that they are successful
	var a1 []byte
	for n, r := range resps {
		if r.Response.Status < 200 || r.Response.Status >= 400 {
			return nil, fmt.Errorf("proposal response was not successful, error code %d, msg %s", r.Response.Status, r.Response.Message)
		}

		if n == 0 {
			a1 = r.Payload
			continue
		}

		if !bytes.Equal(a1, r.Payload) {
			return nil, fmt.Errorf("ProposalResponsePayloads do not match (base64): '%s' vs '%s'",
				b64.StdEncoding.EncodeToString(r.Payload), b64.StdEncoding.EncodeToString(a1))
		}
	}

	// fill endorsements according to their uniqueness
	endorsersUsed := make(map[string]struct{})
	var endorsements []*peer.Endorsement
	for _, r := range resps {
		if r.Endorsement == nil {
			continue
		}
		key := string(r.Endorsement.Endorser)
		if _, used := endorsersUsed[key]; used {
			continue
		}
		endorsements = append(endorsements, r.Endorsement)
		endorsersUsed[key] = struct{}{}
	}

	if len(endorsements) == 0 {
		return nil, fmt.Errorf("no endorsements")
	}

	// add endorser signatures to tx payload
	var tx applicationpb.Tx
	if err := proto.Unmarshal(a1, &tx); err != nil {
		return nil, fmt.Errorf("expected applicationpb.Tx endorsement payload, %s", err.Error())
	}
	nsEndorsements := &applicationpb.Endorsements{}
	for _, end := range endorsements {
		// Deserialize the endorser identity (msppb.Identity from SerializeWithIDOfCert or Serialize)
		endorserIdentity := &msppb.Identity{}
		if err := proto.Unmarshal(end.Endorser, endorserIdentity); err != nil {
			return nil, fmt.Errorf("failed to unmarshal endorser identity: %w", err)
		}
		nsEndorsements.EndorsementsWithIdentity = append(nsEndorsements.EndorsementsWithIdentity,
			&applicationpb.EndorsementWithIdentity{
				Endorsement: end.Signature,
				Identity:    endorserIdentity,
			},
		)
	}
	tx.Endorsements = make([]*applicationpb.Endorsements, len(tx.Namespaces))
	for i := range tx.Namespaces {
		tx.Endorsements[i] = nsEndorsements
	}
	txBytes, err := proto.Marshal(&tx)
	if err != nil {
		return nil, errors.New("can't marshal transaction payload")
	}

	hdr, err := protoutil.UnmarshalHeader(proposal.Header)
	if err != nil {
		return nil, err
	}
	chdr, err := protoutil.UnmarshalChannelHeader(hdr.ChannelHeader)
	if err != nil {
		return nil, err
	}

	// The envelope reuses the proposal's signature header as it is. Endorsers sign over the TxID,
	// so the TxID cannot change after endorsement, and the orderer requires the nonce and creator
	// in the envelope to hash to it. Check that here, so a malformed proposal fails before submit,
	// not silently at the orderer.
	shdr, err := protoutil.UnmarshalSignatureHeader(hdr.SignatureHeader)
	if err != nil {
		return nil, fmt.Errorf("unmarshal proposal signature header: %w", err)
	}
	if len(shdr.Nonce) == 0 {
		return nil, errors.New("proposal signature header has no nonce")
	}
	if err := protoutil.CheckTxID(chdr.TxId, shdr.Nonce, shdr.Creator); err != nil {
		return nil, fmt.Errorf("proposal txid %q does not match its nonce and creator: %w", chdr.TxId, err)
	}
	if signer != nil {
		// The orderer verifies the envelope signature against the creator in the header,
		// so only the invocation's creator can sign the envelope.
		creator, err := signer.Serialize()
		if err != nil {
			return nil, fmt.Errorf("serialize signer: %w", err)
		}
		if !bytes.Equal(creator, shdr.Creator) {
			return nil, errors.New("signer is not the creator of the proposal: the envelope must be signed by the identity that built the invocation")
		}
	}

	// We can use classic Fabric proposals (see fabric.Parse) by replacing the
	// ENDORSER_TRANSACTION with type MESSAGE. We remove the unused Extension.
	if chdr.Type != int32(common.HeaderType_MESSAGE) {
		chdr.Type = int32(common.HeaderType_MESSAGE)
		chdr.Extension = nil
		if hdr.ChannelHeader, err = proto.Marshal(chdr); err != nil {
			return nil, fmt.Errorf("marshal channel header: %w", err)
		}
	}

	// create the payload
	payl := &common.Payload{
		Header: &common.Header{
			ChannelHeader:   hdr.ChannelHeader,
			SignatureHeader: hdr.SignatureHeader,
		},
		Data: txBytes,
	}
	paylBytes, err := protoutil.GetBytesPayload(payl)
	if err != nil {
		return nil, err
	}

	if signer == nil {
		return &common.Envelope{Payload: paylBytes}, nil
	}

	// sign the payload bytes, as the orderer checks the signature over exactly these
	sig, err := signer.Sign(paylBytes)
	if err != nil {
		return nil, fmt.Errorf("sign envelope payload: %w", err)
	}
	return &common.Envelope{Payload: paylBytes, Signature: sig}, nil
}

// NewSubmitter is a convenience constructor that wires together a Fabric-X TxPackager
// and a Submitter for Fabric-X orderers.
//
// The signer may be nil, in which case envelopes are unsigned. Pass one whenever the orderer verifies
// client signatures (ClientSignatureVerificationRequired), which is a sensible production setting
// because the orderer then enforces who may submit transactions. See NewTxPackager.
func NewSubmitter(ctx context.Context, orderers []network.OrdererConf, signer sdk.Signer, waitAfterSubmit time.Duration, logger sdk.Logger) (*network.Submitter, error) {
	return network.NewSubmitter(ctx, orderers, NewTxPackager(signer), waitAfterSubmit, logger)
}
