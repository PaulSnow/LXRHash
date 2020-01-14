package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	lxr "github.com/PaulSnow/LXRHash"
)

var total uint64

var prt chan string

var LX *lxr.LXRHash

func mine(useLXR bool, src []byte) uint64 {

	now := time.Now()
	cd := uint64(0)

	var hashes [][]byte
	rounds := 256

	for i := 0; ; i++ {
		var da []byte
		for b := i; b > 0; b = b >> 8 {
			da = append(da, byte(b))
		}

		data := append(da, src...)

		hashes = append(hashes, data)

		if LX.Version != 2 || len(hashes)>= rounds {
			data := hashes[0]
			var results [][]byte
			if useLXR {
				results = LX.Batch(hashes)
			} else {
				h := sha256.Sum256(data)
				results = append(results,h[:])
			}

			total+= uint64(len(results))

			for _,hash := range results {
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
			hashes = hashes[:0]
		}
	}

	return cd
}

func main() {

	leave := func() {
		fmt.Println("Usage:\n\n" +
			"simMiner <hash> [bits] [version=1 or 2] \n\n" +
			"<hash> is equal to LXRHash to sim mine LXRHash\n" +
			"<hash> is equal to Sha256 to sim mine Sha256\n" +
			"[bits] defaults to 30, but lower numbers can be quicker to initialize\n+" +
			"[version] 1 (or nothing) run the oringional hash, 2 the new hash")
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

	version := "original"

	if hash {
		if len(os.Args) >= 3 {
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
		LX.Version = 1
		if len(os.Args) > 3 {
			v, err := strconv.Atoi(os.Args[3])
			if err != nil || v < 1 || v > 2 {
				fmt.Println(err)
				leave()
			}
			LX.Version = v
			if v == 2 {
				version = "new"
			}
		}
	}

	if hash {
		fmt.Println("Using LXRHash with a ", bits, " bit addressable ByteMap ", version)
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
