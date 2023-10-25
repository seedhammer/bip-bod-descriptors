// This program demonstrates encoding and decoding of descriptors in
// the [bip-psbt-descriptors] format.
//
// [bip-psbt-descriptors]: https://github.com/seedhammer/bips/blob/master/bip-psbt-descriptors.mediawiki
package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"
	"reflect"

	"github.com/btcsuite/btcutil/base58"
	"github.com/seedhammer/bip-psbt-descriptors/desc"
	"github.com/seedhammer/bip-psbt-descriptors/psbt"
)

func main() {
	demoPSBT()
	demoBIPSerializeDesc()
}

func demoBIPSerializeDesc() {
	path := []uint32{
		0x48 + desc.HardenedKeyStart,
		0x00 + desc.HardenedKeyStart,
		0x00 + desc.HardenedKeyStart,
		0x02 + desc.HardenedKeyStart,
	}
	d := desc.OutputDescriptor{
		Name:       "Satoshi's Stash",
		Descriptor: "wsh(sortedmulti(2,@0/<0;1>/*,@1/<0;1>/*,@2/<0;1>/*))",
		BirthBlock: 123456789012345,
		Keys: []psbt.ExtendedKey{
			{
				MasterFingerprint: 0xdc567276,
				Path:              path,
				Key:               base58.Decode("xpub6DiYrfRwNnjeX4vHsWMajJVFKrbEEnu8gAW9vDuQzgTWEsEHE16sGWeXXUV1LBWQE1yCTmeprSNcqZ3W74hqVdgDbtYHUv3eM4W2TEUhpan"),
			},
			{
				MasterFingerprint: 0xf245ae38,
				Path:              path,
				Key:               base58.Decode("xpub6DnT4E1fT8VxuAZW29avMjr5i99aYTHBp9d7fiLnpL5t4JEprQqPMbTw7k7rh5tZZ2F5g8PJpssqrZoebzBChaiJrmEvWwUTEMAbHsY39Ge"),
			},
			{
				MasterFingerprint: 0xc5d87297,
				Path:              path,
				Key:               base58.Decode("xpub6DjrnfAyuonMaboEb3ZQZzhQ2ZEgaKV2r64BFmqymZqJqviLTe1JzMr2X2RfQF892RH7MyYUbcy77R7pPu1P71xoj8cDUMNhAMGYzKR4noZ"),
			},
		},
	}
	p, err := desc.Encode(d)
	if err != nil {
		panic(err)
	}
	buf := new(bytes.Buffer)
	psbt.Encode(buf, p)
	enc := buf.Bytes()
	fmt.Printf("\nSerialized descriptor (length %d):\n%x\n\nDecoded descriptor:\n", len(enc), enc)
	p2, _, err := psbt.Decode(enc)
	if err != nil {
		panic(err)
	}
	d2, err := desc.Decode(p2)
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(d, d2) {
		panic(fmt.Errorf("decoded descriptor does not match\nGot: %+v\nExpected: %+v\n", d2, d))
	}
	fmt.Printf("Name: %s\n", d2.Name)
	fmt.Printf("Descriptor: %s\n", d2.Descriptor)
	fmt.Printf("Birth block: %d\n", d2.BirthBlock)
	for _, k := range d2.Keys {
		fmt.Printf("xpub: [%x", k.MasterFingerprint)
		for _, p := range k.Path {
			if p >= desc.HardenedKeyStart {
				fmt.Printf("/%xh", p-desc.HardenedKeyStart)
			} else {
				fmt.Printf("/%x", p)
			}
		}
		fmt.Printf("]%s\n", base58.Encode(k.Key))
	}
}

func demoPSBT() {
	p, err := hex.DecodeString("70736274ff0100750200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf60000000000feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1300000100fda5010100000000010289a3c71eab4d20e0371bbba4cc698fa295c9463afa2e397f8533ccb62f9567e50100000017160014be18d152a9b012039daf3da7de4f53349eecb985ffffffff86f8aa43a71dff1448893a530a7237ef6b4608bbb2dd2d0171e63aec6a4890b40100000017160014fe3e9ef1a745e974d902c4355943abcb34bd5353ffffffff0200c2eb0b000000001976a91485cff1097fd9e008bb34af709c62197b38978a4888ac72fef84e2c00000017a914339725ba21efd62ac753a9bcd067d6c7a6a39d05870247304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c012103d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f210502483045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01210223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab300000000000000")
	if err != nil {
		panic(err)
	}
	fmt.Println("Parsed PSBT:")
	f, _, err := psbt.Decode(p)
	if err != nil {
		log.Fatal(err)
	}
	for _, e := range f.Global {
		switch e.Type {
		case psbt.GLOBAL_UNSIGNED_TX:
			fmt.Println("unsigned tx!")
		case psbt.GLOBAL_XPUB:
			fmt.Println("xpub!")
		}
	}
	for _, e := range f.Input {
		fmt.Println("input type:", e.Type)
	}
	for _, e := range f.Output {
		fmt.Println("output type:", e.Type)
	}
}
