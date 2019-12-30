package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math/bits"
	"strings"
	"time"

	ct "github.com/google/certificate-transparency-go"
	cttls "github.com/google/certificate-transparency-go/tls"
	ctx509 "github.com/google/certificate-transparency-go/x509"

	"github.com/murakmii/ct-sample/util"
)

type (
	STHResponse struct {
		TreeSize          uint64 `json:"tree_size"`
		Timestamp         uint64 `json:"timestamp"`
		SHA256RootHash    []byte `json:"sha256_root_hash"`
		TreeHeadSignature []byte `json:"tree_head_signature"`
	}

	EntriesResponse struct {
		Entries []EntryResponse `json:"entries"`
	}

	EntryResponse struct {
		LeafInput []byte `json:"leaf_input"`
	}

	ProofByHashResponse struct {
		LeafIndex uint64   `json:"leaf_index"`
		AuditPath [][]byte `json:"audit_path"`
	}
)

const (
	googleRocketeerLogID = "7ku9t3XOYLrhQmkfq+GeZqMPfl+wctiDAMR7iXqo/cs="
)

var (
	ErrNotPrecert = fmt.Errorf("not pre-cert")
)

func main() {
	logs, err := util.NewLogs(nil)
	if err != nil {
		panic(err)
	}

	log, err := logs.FindByLogID(googleRocketeerLogID)
	if err != nil {
		panic(err)
	}

	var previousLogs uint64
	for {
		go func() {
			fmt.Println("start to get STH")
			sthResp := getSTH(log)

			if previousLogs == 0 || previousLogs == sthResp.TreeSize {
				previousLogs = sthResp.TreeSize
				return
			}

			fmt.Printf("Tree size: %d -> %d\n", previousLogs, sthResp.TreeSize)

			entriesResp := getEntries(log, previousLogs-1, sthResp.TreeSize-1)
			previousLogs = sthResp.TreeSize

			fmt.Printf("received: %d\n", len(entriesResp.Entries))
			for _, entry := range entriesResp.Entries {
				cert, err := entry.Cert()
				if err == ErrNotPrecert {
					continue
				} else if err != nil {
					panic(err)
				}

				if strings.HasSuffix(cert.Subject.CommonName, ".com") {
					fmt.Printf("issued: %s\n", cert.Subject.String())
				}
			}
		}()

		time.Sleep(5 * time.Second)
	}
}

// STHを取得し、署名を検証した上で返す
func getSTH(log *util.Log) *STHResponse {
	sthResp := &STHResponse{}
	if err := util.GetAsJson(log.GetSTHURL(), sthResp); err != nil {
		panic(err)
	}

	pubKey, err := log.PublicKey()
	if err != nil {
		panic(err)
	}

	if err := sthResp.CheckSignature(pubKey); err != nil {
		panic(err)
	}

	return sthResp
}

// get-sthのレスポンスに含まれる署名をログサーバーの公開鍵を用いて検証する
func (sthResp *STHResponse) CheckSignature(publicKey interface{}) error {
	// 署名元のデータを構成する
	var hash [32]byte
	copy(hash[:], sthResp.SHA256RootHash)

	ths := ct.TreeHeadSignature{
		Version:        0, // 現状のCTの仕様では必ず0
		SignatureType:  1, // TreeHeadSignature の場合1を指定する仕様
		Timestamp:      sthResp.Timestamp,
		TreeSize:       sthResp.TreeSize,
		SHA256RootHash: hash,
	}
	data, err := cttls.Marshal(ths)
	if err != nil {
		return err
	}

	// get-sthのレスポンスに含まれる署名からDigitallySignedとする
	ds := cttls.DigitallySigned{}
	rest, err := cttls.Unmarshal(sthResp.TreeHeadSignature, &ds)
	if err != nil {
		return err
	} else if len(rest) > 0 {
		return fmt.Errorf("invalid signature is in sth")
	}

	return cttls.VerifySignature(publicKey, data, ds)
}

// 一連の証明書を取得する
func getEntries(log *util.Log, start, end uint64) *EntriesResponse {
	entriesURL := log.GetEntriesURL(start, end)
	entriesResp := &EntriesResponse{}
	if err := util.GetAsJson(entriesURL, entriesResp); err != nil {
		panic(err)
	}

	return entriesResp
}

// ログエントリーが事前証明書を表す場合だけそれを返す
func (entryResp *EntryResponse) Cert() (*ctx509.Certificate, error) {
	leaf := &ct.MerkleTreeLeaf{}
	rest, err := cttls.Unmarshal(entryResp.LeafInput, leaf)
	if err != nil {
		return nil, err
	} else if len(rest) > 0 {
		return nil, fmt.Errorf("invalid leaf in entry")
	}

	// NOTE: 本当はleaf_inputが正しいものかどうかを、
	//       ログサーバーが構成しているMerkle Treeに
	// 　　　　照らし合わせて検証する、という処理も必要なのですが、
	//       本誌では紙面の都合上省略しています

	if leaf.TimestampedEntry.EntryType != ct.PrecertLogEntryType {
		return nil, ErrNotPrecert
	}

	cert := leaf.TimestampedEntry.PrecertEntry.TBSCertificate
	return ctx509.ParseTBSCertificate(cert)
}

// このログエントリーを検証するためのAudit Pathを取得するためのハッシュ値を返す
func (entryResp *EntryResponse) LeafHash() []byte {
	input := append([]byte{0x00}, entryResp.LeafInput...)
	hash := sha256.Sum256(input)
	return hash[:]
}

// NOTE: この関数は同人誌では「Certificate Transparency in Action」中では紹介していない。
//       MerkleTreeに照らし合わせてログエントリーを検証するにはこのような実装が必要。
//       同等の処理は github.com/google/certificate-transparency-go でも提供されている(LogVerifierのVerifyInclusionProofメソッド)
func checkProof(leafHash []byte, proofResp *ProofByHashResponse, rootHash []byte, size uint64) error {
	idx := proofResp.LeafIndex
	hash := leafHash
	border := len(proofResp.AuditPath) - calcLeftTreeCount(idx, size)

	for _, proof := range proofResp.AuditPath[:border] {
		data := []byte{0x01}
		if idx&1 == 0 {
			data = append(data, append(hash, proof...)...)
		} else {
			data = append(data, append(proof, hash...)...)
		}

		h := sha256.Sum256(data)
		hash = h[:]
		idx = idx >> 1
	}

	for _, proof := range proofResp.AuditPath[border:] {
		h := sha256.Sum256(append([]byte{0x01}, append(proof, hash...)...))
		hash = h[:]
	}

	if !bytes.Equal(hash, rootHash) {
		return fmt.Errorf("mismatch computed hash and root hash")
	}

	return nil
}

func calcLeftTreeCount(idx uint64, size uint64) int {
	max := uint64(1 << uint64(bits.Len64(size-1)))
	half := max / 2

	if idx < half || size == max-1 {
		return 0
	}

	return 1 + calcLeftTreeCount(idx-half, size-half)
}
