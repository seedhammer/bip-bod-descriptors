// This program demonstrates encoding and decoding of descriptors in
// the [bip-bod-descriptors] format.
//
// [bip-bod-descriptors]: https://github.com/seedhammer/bips/blob/master/bip-bod-descriptors.mediawiki
package main

import (
	"bytes"
	"fmt"
	"reflect"

	"github.com/btcsuite/btcutil/base58"
	"github.com/seedhammer/bip-bod-descriptors/bod"
	"github.com/seedhammer/bip-bod-descriptors/psbt"
)

func main() {
	path := []uint32{
		0x48 + bod.HardenedKeyStart,
		0x00 + bod.HardenedKeyStart,
		0x00 + bod.HardenedKeyStart,
		0x02 + bod.HardenedKeyStart,
	}
	d := bod.OutputDescriptor{
		Name:       "Satoshi's Stash",
		Descriptor: "wsh(sortedmulti(2,@0/<0;1>/*,@1/<0;1>/*,@2/<0;1>/*))",
		BirthBlock: 123456789012345,
		Keys: []bod.ExtendedKey{
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
	p, err := bod.Encode(d)
	if err != nil {
		panic(err)
	}
	buf := new(bytes.Buffer)
	psbt.Encode(bod.Magic, buf, []psbt.Map{p.Global, p.Key})
	enc := buf.Bytes()
	fmt.Printf("\nSerialized descriptor (length %d):\n%x\n\nDecoded descriptor:\n", len(enc), enc)
	p2, _, err := psbt.Decode(bod.Magic, enc)
	if err != nil {
		panic(err)
	}
	d2, err := bod.Decode(bod.File{Global: p2[0], Key: p2[1]})
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
			if p >= bod.HardenedKeyStart {
				fmt.Printf("/%xh", p-bod.HardenedKeyStart)
			} else {
				fmt.Printf("/%x", p)
			}
		}
		fmt.Printf("]%s\n", base58.Encode(k.Key))
	}
}
