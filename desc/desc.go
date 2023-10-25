// Package descriptors implements the [bip-psbt-descriptors] proposal.
//
// [bip-psbt-descriptors]: https://github.com/seedhammer/bips/blob/master/bip-psbt-descriptors.mediawiki
package desc

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"unicode/utf8"

	"github.com/seedhammer/bip-psbt-descriptors/psbt"
)

const HardenedKeyStart = 0x80000000 // 2^31

const (
	// The field type for the output descriptor.
	GLOBAL_OUTPUT_DESCRIPTOR = 0x07
)

type OutputDescriptor struct {
	Name       string
	BirthBlock uint64
	Descriptor string
	Keys       []psbt.ExtendedKey
}

func Encode(desc OutputDescriptor) (psbt.File, error) {
	key := new(bytes.Buffer)
	psbt.EncodeVarUInt(key, desc.BirthBlock)
	key.Write([]byte(desc.Name))

	p := []psbt.Entry{
		{
			Type:  GLOBAL_OUTPUT_DESCRIPTOR,
			Key:   key.Bytes(),
			Value: []byte(desc.Descriptor),
		},
	}

	// Write a map for each key.
	for _, k := range desc.Keys {
		var mfpAndPath []byte
		mfpAndPath = binary.BigEndian.AppendUint32(mfpAndPath, k.MasterFingerprint)
		for _, p := range k.Path {
			mfpAndPath = binary.LittleEndian.AppendUint32(mfpAndPath, p)
		}
		p = append(p, psbt.Entry{
			Type:  psbt.GLOBAL_XPUB,
			Key:   k.Key,
			Value: mfpAndPath,
		})
	}

	return psbt.File{Global: p}, nil
}

func Decode(f psbt.File) (OutputDescriptor, error) {
	var desc OutputDescriptor
	for _, e := range f.Global {
		switch t := e.Type; t {
		case GLOBAL_OUTPUT_DESCRIPTOR:
			bb, n, err := psbt.DecodeVarUInt(e.Key)
			if err != nil {
				return OutputDescriptor{}, nil
			}
			desc.BirthBlock = bb
			desc.Name = string(e.Key[n:])
			if !utf8.ValidString(desc.Name) {
				return OutputDescriptor{}, fmt.Errorf("desc: invalid descriptor name: %q", desc.Name)
			}
			desc.Descriptor = string(e.Value)
		case psbt.GLOBAL_XPUB:
			k, err := psbt.DecodeXPUB(e)
			if err != nil {
				return OutputDescriptor{}, fmt.Errorf("desc: invalid key at index %d: %w", len(desc.Keys), err)
			}
			desc.Keys = append(desc.Keys, k)
		}
	}
	return desc, nil
}
