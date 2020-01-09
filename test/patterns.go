package main

// LXRHash holds one instance of a hash function with a specific seed and map size
type LXRHash struct {
	ByteMap     []byte // Integer Offsets
	MapSize     uint64 // Size of the translation table
	MapSizeBits uint64 // Size of the ByteMap in Bits
	Passes      uint64 // Passes to generate the rand table
	Seed        uint64 // An arbitrary number used to create the tables.
	HashSize    uint64 // Number of bytes in the hash
	verbose     bool
}

// Hash takes the arbitrary input and returns the resulting hash of length HashSize
func (lx LXRHash) Hash(src []byte) []byte {
	// as accumulates the state as we walk through applying the source data through the lookup map
	hs := make([]uint64, lx.HashSize)
	// and combine it with the state we are building up.
	var as = lx.Seed
	// We keep a series of states, and roll them along through each byte of source processed.
	var s1, s2, s3 uint64
	// Since MapSize is specified in bits, the index mask is the size-1
	mk := lx.MapSize - 1

	B := func(v uint64) uint64 { return uint64(lx.ByteMap[v&mk]) }
	b := func(v uint64) byte { return byte(B(v)) }

	faststep := func(v2 uint64, idx uint64) {
		b := B(as ^ v2)
		as = as<<7 ^ as>>5 ^ v2<<20 ^ v2<<16 ^ v2 ^ b<<20 ^ b<<12 ^ b<<4
		s1 = s1<<9 ^ s1>>3 ^ hs[idx] ^ b
		hs[idx] = s1 ^ as
		s1, s2, s3 = s3, s1, s2
	}
	idx := uint64(0)
	// Fast spin to prevent caching state
	for _, v2 := range src {
		if idx >= lx.HashSize { // Use an if to avoid modulo math
			idx = 0
		}
		faststep(uint64(v2), idx)
		idx++
	}
	return nil
}

func main() {}
