// Copyright (c) of parts are held by the various contributors
// Licensed under the MIT License. See LICENSE file in the project root for full license information.
package lxr

import "crypto/sha256"

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
func (lx LXRHash) Hash(input []byte) (bytes []byte) {
	hashBytes := make([]uint64, lx.HashSize)           // Each return byte is uint64 until the ned
	var as = lx.Seed                                   // "accumulated state".  Gets modified as we go
	mk := lx.MapSize - 1                               // Mask for the mapSize which must be a power of 2
	s := sha256.Sum256(input)                          // Do a double sha256 of our input, then we modify
	s = sha256.Sum256(s[:])                            //   the resulting hash to get constant performance
	src := s[:]                                        //   independent of the input length.
	ub := func(i int) uint64 { return uint64(src[i]) } // Just tighten up the next line
	as ^= ub(0) ^ ub(1)<<8 ^ ub(2)<<16 ^ ub(3)<<24     // Hash as with first 4 bytes of sha256 hash
	for i := uint64(0); i < 3; i++ {                   // Make 8 passes through the source bytes
		idx := 0
		for _, b := range src { // For every byte in the hash of the input
			v2 := uint64(b)                        // Do the conversion of the byte to uint64 here rather than in all the following references
			as ^= as<<23 ^ as>>11 ^ hashBytes[idx] // Modify the state by the current hashBytes[] value.
			ub := func(i uint64) uint64 {          // Tighten up the references in the code that follows
				return uint64(lx.ByteMap[i])
			}
			as = as<<13 ^ as>>1 ^ ub((v2^as)&mk)                         // Look up a byte with our current state, mod as
			as = as<<11 ^ as>>3 ^ ub((v2^as)&mk)                         // Look up a byte with our current state, mod as
			as = as<<17 ^ as>>5 ^ ub((v2^as)&mk)                         // Look up a byte with our current state, mod as
			as = as<<19 ^ as>>7 ^ ub((v2^as)&mk)                         // Look up a byte with our current state, mod as
			as = as<<13 ^ as>>1 ^ ub((v2^as)&mk)                         // Look up a byte with our current state, mod as
			as = as<<11 ^ as>>3 ^ ub((v2^as)&mk)                         // Look up a byte with our current state, mod as
			as = as<<17 ^ as>>5 ^ ub((v2^as)&mk)                         // Look up a byte with our current state, mod as
			as = as<<19 ^ as>>7 ^ ub((v2^as)&mk)                         // Look up a byte with our current state, mod as
			as = as<<13 ^ as>>1 ^ ub((v2^as)&mk)                         // Look up a byte with our current state, mod as
			as = as<<11 ^ as>>3 ^ ub((v2^as)&mk)                         // Look up a byte with our current state, mod as
			hashBytes[idx] = hashBytes[idx]<<17 ^ hashBytes[idx]>>1 ^ as // Modify the hashByte value with the state change
			idx++                                                        // Wall through the hashBytes with a prime number walk
		}
	}

	for i := len(hashBytes) - 1; i >= 0; i-- { // Convert all the hashBytes to a byte and return the result
		bytes = append(bytes, byte(hashBytes[i]))
	}

	return bytes
}
