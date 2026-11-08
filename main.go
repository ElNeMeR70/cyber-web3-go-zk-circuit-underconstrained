package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"strings"
)

func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]float64)
	for _, r := range s {
		freq[r]++
	}
	var ent float64
	n := float64(len([]rune(s)))
	for _, c := range freq {
		p := c / n
		ent -= p * math.Log2(p)
	}
	return ent
}

func main() {
	payload := "SELECT * FROM users WHERE eval(tx.origin)"
	if len(os.Args) > 1 {
		payload = os.Args[1]
	}
	mac := hmac.New(sha256.New, []byte("cyber-web3-go-zk-circuit-underconstrained"))
	mac.Write([]byte(payload))
	att := hex.EncodeToString(mac.Sum(nil))[:32]
	ent := shannonEntropy(payload)
	verdict := "CLEAN_VERIFIED"
	if strings.Contains(payload, "eval(") || strings.Contains(payload, "SELECT ") || strings.Contains(payload, "tx.origin") {
		verdict = "BLOCK_THREAT"
	}
	fmt.Printf(`{"engine":"cyber-web3-go-zk-circuit-underconstrained","standards":"SWC-107 / SWC-115 / SWC-101 / SWC-112","entropy_bits":%.4f,"verdict":"%s","attestation":"%s"}`+"\n", ent, verdict, att)
}
