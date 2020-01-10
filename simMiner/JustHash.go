package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	lxr "github.com/pegnet/LXRHash"
)

var total uint64

var prt chan string

var LX *lxr.LXRHash

func mine(useLXR bool, src []byte) uint64 {

	now := time.Now()
	cd := uint64(0)
	for i := 0; ; i++ {
		var da []byte
		for b := i; b > 0; b = b >> 8 {
			da = append(da, byte(b))
		}

		data := append(da, src...)

		var hash []byte
		if useLXR {
			hash = LX.Hash(data)
		} else {
			h := sha256.Sum256(data)
			hash = h[:]
		}

		total++

		d := uint64(0)
		for i := 0; i < 8; i++ {
			d = d<<8 + uint64(hash[i])
		}
		if cd < d {
			cd = d
			running := time.Since(now)
			hps := float64(total) / running.Seconds()
			prt <- fmt.Sprintf("%10d %16x %8x %10.0f hps\n", total, cd, i, hps)

		}
	}
	return cd
}

func main() {

	leave := func() {
		fmt.Println("Usage:\n\n" +
			"simMiner <hash> [bits]\n\n" +
			"<hash> is equal to LXRHash to sim mine LXRHash\n" +
			"<hash> is equal to Sha256 to sim mine Sha256\n" +
			"[bits] defaults to 30, but lower numbers can be quicker to initialize")
		os.Exit(0)
	}

	if len(os.Args) < 2 {
		leave()
	}

	h := strings.ToLower(os.Args[1])
	hash := h == "lxrhash"
	if !hash && h != "sha256" {
		leave()
	}

	bits := lxr.MapSizeBits
	if hash {
		if len(os.Args) == 3 {
			b, err := strconv.Atoi(os.Args[2])
			if err != nil {
				fmt.Println(err)
				leave()
			}
			if b > 40 || b < 8 {
				fmt.Println("Bits specified must be at least 8 and less than or equal to 40.  40 bits is 1 TB")
			}
			bits = uint64(b)
		}

		LX = new(lxr.LXRHash)
		LX.Init(lxr.Seed, bits, lxr.HashSize, lxr.Passes)
	}

	if hash {
		fmt.Println("Using LXRHash with a ", bits, " bit addressable ByteMap")
	} else {
		fmt.Println("Using Sha256")
	}

	prt = make(chan string, 500)
	s := sha256.Sum256([]byte("one test"))

	go mine(hash, s[:])

	now := time.Now()
	for {
		select {
		case s := <-prt:
			fmt.Print(s)
			continue
		default:
		}
		time.Sleep(10 * time.Second)
		running := time.Since(now)
		hps := float64(total) / running.Seconds()
		prt <- fmt.Sprintf("%10d %16s %8s %10.0f hps\n", total, "", "", hps)

	}
}
