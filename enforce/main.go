package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptrace"
	"os"

	"github.com/murakmii/ct-sample/util"

	ct "github.com/google/certificate-transparency-go"

	cttls "github.com/google/certificate-transparency-go/tls"
	ctx509 "github.com/google/certificate-transparency-go/x509"
)

var (
	sctOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
)

func main() {
	logs, err := util.NewLogs(nil)
	if err != nil {
		panic(err)
	}

	client := &http.Client{}

	req, err := http.NewRequest("GET", os.Args[1], nil)
	if err != nil {
		panic(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	req = req.WithContext(httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			containsSCT, _ := checkSCT(logs, state.PeerCertificates[0])
			if !containsSCT {
				fmt.Fprintf(os.Stderr, "no SCT\n")
				cancel()
			}
		},
	}))

	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	fmt.Printf("responded status code: %d\n", resp.StatusCode)
}

func checkSCT(logs util.Logs, cert *x509.Certificate) (bool, error) {
	contains := 0

	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(sctOID) {
			continue
		}

		serializedSCTBytes := make([]byte, 0)
		rest, err := asn1.Unmarshal(ext.Value, &serializedSCTBytes)
		if err != nil {
			return false, err
		} else if len(rest) != 0 {
			return false, fmt.Errorf("invalid SCT extension")
		}

		serializedSCTs := ctx509.SignedCertificateTimestampList{}
		rest, err = cttls.Unmarshal(serializedSCTBytes, &serializedSCTs)
		if err != nil {
			return false, err
		} else if len(rest) > 0 {
			return false, fmt.Errorf("invalid SCT list")
		}

		for _, serializedSCT := range serializedSCTs.SCTList {
			sct := ct.SignedCertificateTimestamp{}
			rest, err = cttls.Unmarshal(serializedSCT.Val, &sct)
			if err != nil {
				return false, err
			} else if len(rest) > 0 {
				return false, fmt.Errorf("invalid serialized SCT")
			}

			log, err := logs.FindByLogID(base64.StdEncoding.EncodeToString(sct.LogID.KeyID[:]))
			if err != nil {
				return false, err
			}

			fmt.Printf("Log: %s(%s)\n", log.Operator(), log.Description())
			contains++
		}

	}

	return contains > 0, nil
}
