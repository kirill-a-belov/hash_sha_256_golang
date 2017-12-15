package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

//Some constants - bits of roots of primes - it need for algorithm, they already preset by SHA inventors
var K = [64]uint32{
	0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
	0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
	0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
	0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
	0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
	0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
	0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
	0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2}

func SHA_256(input []byte) []byte {

	// 1. Make a cryptographic padding
	// We should add 1 + some (n) 0 bits such as input + 1 + n x 0 mod 512 = 448
	// and add input length (as 64 bit) after: 448 + 64 = 512
	// With this addition we can divide our input message on whole number of 512 blocks
	// But we can work only with 8 bits minimum, so we should add bytes (Cryptographic padding)
	//In Golang type byte just alias to uint8.

	// initialisatiom
	var H [8]uint32 = [8]uint32{
		0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19}
	messageWithPadding := []uint8{}

	// 1.1 Finding how many bytes we should add to original message
	paddingLength := (448 - (len(input) * 8)) % 512 / 8
	if paddingLength < 0 { // we need another 512 block
		paddingLength = paddingLength + 512/8
	}

	//// 1.2 Add padding to original message
	messageWithPadding = append(messageWithPadding, input...)

	if paddingLength != 0 {
		// add first byte with 1 (0x80 = 10000000)
		messageWithPadding = append(messageWithPadding, 0x80)
	}
	for i := 0; i < (paddingLength - 1); i++ {
		// add other null bytes (0 = 10000000)
		messageWithPadding = append(messageWithPadding, 0x00)
	}

	//// 1.3 Add original message length as big-endian 64-bit int
	origMesLength := make([]uint8, 8)
	binary.BigEndian.PutUint64(origMesLength, uint64(len(input)*8))
	messageWithPadding = append(messageWithPadding, origMesLength...)

	// 2. Processing augmented message by 512-bits (64-bytes) chunks(
	for i := 0; i < len(messageWithPadding); i += 64 {
		// generate chunk
		chunk := messageWithPadding[i : i+64]

		// brake chunks on 16 32-bits (4-bytes, type uint32) words
		words := [64]uint32{}
		j := 0
		for i := 0; i < 64; i += 4 {
			words[j] = binary.BigEndian.Uint32(chunk[i : i+4])
			j++
		}

		// add generated extra 48 words
		for j := 16; j < 64; j++ {
			s0 := rightRotate(words[j-15], 7) ^ rightRotate(words[j-15], 18) ^ rightShift(words[j-15], 3)
			s1 := rightRotate(words[j-2], 17) ^ rightRotate(words[j-2], 19) ^ rightShift(words[j-2], 10)
			words[j] = words[j-16] + s0 + words[j-7] + s1
		}

		// initialize working variables
		a := H[0]
		b := H[1]
		c := H[2]
		d := H[3]
		e := H[4]
		f := H[5]
		g := H[6]
		h := H[7]

		// compression function main loop
		for l := 0; l < 63; l++ {

			summ0 := rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22)
			ma := (a & b) ^ (a & c) ^ (b & c)
			temp2 := summ0 + ma
			summ1 := rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25)
			ch := (e & f) ^ (^e & g)
			temp1 := h + summ1 + ch + K[l] + words[l]

			h = g
			g = f
			f = e
			e = d + temp1
			d = c
			c = b
			b = a
			a = temp1 + temp2
		}
		// current hash value
		H[0] = H[0] + a
		H[1] = H[1] + b
		H[2] = H[2] + c
		H[3] = H[3] + d
		H[4] = H[4] + e
		H[5] = H[5] + f
		H[6] = H[6] + g
		H[7] = H[7] + h

	}

	// 3. Collecting result hash sum
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, H); err != nil {
		panic(err)
	} else {
		return buf.Bytes()
	}
}

func rightShift(input uint32, num uint8) uint32 {
	//Bitwise right shift
	return input >> num
}

func rightRotate(input uint32, num uint8) uint32 {
	//Bitwise circular right shift
	return (input >> num) | (input << (32 - num))
}

func main() {
	fmt.Println("Hash input string: ")
	str := []byte("Bitcoin is the most popular cryptocurrency")
	fmt.Println(string(str))
	fmt.Println()

	fmt.Println("Make hash by std lib")

	x := sha256.New()
	x.Write(str)
	y := x.Sum(nil)
	fmt.Printf("%x\n", y)
	fmt.Println()

	fmt.Println("Make hash by custom realisation")

	fmt.Printf("%x\n", SHA_256(str))

}
