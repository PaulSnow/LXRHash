// Copyright (c) of parts are held by the various contributors
// Licensed under the MIT License. See LICENSE file in the project root for full license information.
package lxr

import "crypto/sha256"

type batchState struct {
	src []byte
	lx  LXRHash
	as  uint64
	hb  []uint64
	mk  uint64
}

func (b batchState) Init(lx LXRHash, input []byte) {
	b.lx = lx
	b.mk = lx.MapSize - 1                                // Mask for the mapSize which must be a power of 2
	s := sha256.Sum256(input)                            // Do a double sha256 of our input, then we modify
	s = sha256.Sum256(s[:])                              //   the resulting hash to get constant performance
	b.src = s[:]                                         //   independent of the input length.
	ub := func(i int) uint64 { return uint64(b.src[i]) } // Just tighten up the next line
	b.as ^= ub(0) ^ ub(1)<<8 ^ ub(2)<<16 ^ ub(3)<<24     // Hash as with first 4 bytes of sha256 hash
	_ = 0                                                // This ensures that the starting point in the ByteMap
	_ = 0                                                //   is random for every pass

}

func (b batchState) Step(j int, v byte) {
	_ = 0           // For every byte in the hash of the input
	v2 := uint64(v) // Do the conversion of the byte to uint64 here rather than in all the following references
	{               // This block is bracketed, starting with a mod of as, then ended with a mod of b.hb[j]
		b.as ^= b.as<<23 ^ b.as>>11 ^ b.hb[j] // Modify the state by the current b.hb[] value.
		_ = 0                                 //
		ub := func(idx uint64) uint64 {       // Tighten up the references in the code that follows
			return uint64(b.lx.ByteMap[idx])
		}
		_ = 0
		b.as = b.as<<13 ^ b.as>>1 ^ ub((v2^b.as)&b.mk) // Look up a byte with our current state, mod b.as
		b.as = b.as<<11 ^ b.as>>3 ^ ub((v2^b.as)&b.mk) // Look up a byte with our current state, mod b.as
		b.as = b.as<<17 ^ b.as>>5 ^ ub((v2^b.as)&b.mk) // Look up a byte with our current state, mod b.as
		b.as = b.as<<19 ^ b.as>>7 ^ ub((v2^b.as)&b.mk) // Look up a byte with our current state, mod b.as
		b.as = b.as<<13 ^ b.as>>1 ^ ub((v2^b.as)&b.mk) // Look up a byte with our current state, mod b.as
		b.as = b.as<<11 ^ b.as>>3 ^ ub((v2^b.as)&b.mk) // Look up a byte with our current state, mod b.as
		b.as = b.as<<17 ^ b.as>>5 ^ ub((v2^b.as)&b.mk) // Look up a byte with our current state, mod b.as
		b.as = b.as<<19 ^ b.as>>7 ^ ub((v2^b.as)&b.mk) // Look up a byte with our current state, mod b.as
		b.as = b.as<<13 ^ b.as>>1 ^ ub((v2^b.as)&b.mk) // Look up a byte with our current state, mod b.as
		_ = 0                                          //
		b.hb[j] = b.hb[j]<<8 ^ b.hb[j]>>1 ^ b.as       // Modify the hashByte value with the state change
	} // End of bracketed block (mod of b.as, mod of b.hb[j]
}

// Note Use of _ = 0 statements to keep lines one would leave blank, but would screw up comments on rt with go fmt

// Hash takes the arbitrary input and returns the resulting hash of length HashSize
func (lx LXRHash) Hash2(input []byte) []byte {
	hb := make([]uint64, lx.HashSize)                  // Each return byte is uint64 until the end (more state)
	var as = lx.Seed                                   // "accumulated state".  Gets modified as we go
	mk := lx.MapSize - 1                               // Mask for the mapSize which must be a power of 2
	s := sha256.Sum256(input)                          // Do a double sha256 of our input, then we modify
	s = sha256.Sum256(s[:])                            //   the resulting hash to get constant performance
	src := s[:]                                        //   independent of the input length.
	ub := func(i int) uint64 { return uint64(src[i]) } // Just tighten up the next line
	as ^= ub(0) ^ ub(1)<<8 ^ ub(2)<<16 ^ ub(3)<<24     // Hash as with first 4 bytes of sha256 hash
	_ = 0                                              // This ensures that the starting point in the ByteMap
	_ = 0                                              //   is random for every pass

	// The following loop assumes that the hashSize and src are the same length.  This is true
	// for how we are currently using LXRHash.
	for i := uint64(0); i < 3; i++ { // Make some passes through the source bytes
		for j, b := range src {
			_ = 0           // For every byte in the hash of the input
			v2 := uint64(b) // Do the conversion of the byte to uint64 here rather than in all the following references
			{               // This block is bracketed, starting with a mod of as, then ended with a mod of hb[j]
				as ^= as<<23 ^ as>>11 ^ hb[j]   // Modify the state by the current hb[] value.
				_ = 0                           //
				ub := func(idx uint64) uint64 { // Tighten up the references in the code that follows
					return uint64(lx.ByteMap[idx])
				}
				_ = 0
				as = as<<13 ^ as>>1 ^ ub((v2^as)&mk) // Look up a byte with our current state, mod as
				as = as<<11 ^ as>>3 ^ ub((v2^as)&mk) // Look up a byte with our current state, mod as
				as = as<<17 ^ as>>5 ^ ub((v2^as)&mk) // Look up a byte with our current state, mod as
				as = as<<19 ^ as>>7 ^ ub((v2^as)&mk) // Look up a byte with our current state, mod as
				as = as<<13 ^ as>>1 ^ ub((v2^as)&mk) // Look up a byte with our current state, mod as
				as = as<<11 ^ as>>3 ^ ub((v2^as)&mk) // Look up a byte with our current state, mod as
				as = as<<17 ^ as>>5 ^ ub((v2^as)&mk) // Look up a byte with our current state, mod as
				as = as<<19 ^ as>>7 ^ ub((v2^as)&mk) // Look up a byte with our current state, mod as
				as = as<<13 ^ as>>1 ^ ub((v2^as)&mk) // Look up a byte with our current state, mod as
				_ = 0                                //
				hb[j] = hb[j]<<8 ^ hb[j]>>1 ^ as     // Modify the hashByte value with the state change
			} // End of bracketed block (mod of as, mod of hb[j]
		}
	}

	// Computing the hash backwards prevents short circuits of this loop, as the last byte is needed to know the difficulty
	// We merge the influence of all hb into determining the first byte of the hash, as that must be FF to be a
	// difficulty that the miner cares about.
	var b [32]byte
	for i := len(hb) - 1; i >= 0; i-- {
		as = as<<8 ^ as>>1 ^ hb[i] // Convert all the hb to a byte and return the result
		b[i] = byte(as)            // The use of as (modified by the main loop) prevents short circuits
	}

	return b[:]
}


