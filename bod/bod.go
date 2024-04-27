// Package descriptors implements the [bip-bod-descriptors] proposal.
//
// [bip-bod-descriptors]: https://github.com/seedhammer/bips/blob/master/bip-bod-descriptors.mediawiki
package bod

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/seedhammer/bip-bod-descriptors/psbt"
)

const HardenedKeyStart = 0x80000000 // 2^31

const (
	Magic = "bod\xff"
	// The field type for the output descriptor.
	GLOBAL_OUTPUT_DESCRIPTOR psbt.KeyType = 0x00

	KEY_XPUB psbt.KeyType = 0x01
)

type ExtendedKey struct {
	MasterFingerprint uint32
	Path              []uint32
	Key               []byte
}

func DecodeXPUB(e psbt.Entry) (ExtendedKey, error) {
	if e.Type != KEY_XPUB {
		return ExtendedKey{}, errors.New("psbt: map entry not a PSBT_GLOBAL_XPUB")
	}
	val := e.Value
	if len(val) < 4 || len(val)%4 != 0 {
		return ExtendedKey{}, io.ErrUnexpectedEOF
	}
	k := ExtendedKey{
		Key: e.Key,
	}
	k.MasterFingerprint = binary.BigEndian.Uint32(val)
	val = val[4:]
	for len(val) > 0 {
		p := binary.LittleEndian.Uint32(val)
		val = val[4:]
		k.Path = append(k.Path, p)
	}
	return k, nil
}

type OutputDescriptor struct {
	Name       string
	BirthBlock uint64
	Descriptor string
	Keys       []ExtendedKey
}

type File struct {
	Global psbt.Map
	Key    psbt.Map
}

func Encode(desc OutputDescriptor) (File, error) {
	key := new(bytes.Buffer)
	psbt.EncodeVarUInt(key, desc.BirthBlock)
	key.Write([]byte(desc.Name))

	f := File{
		Global: psbt.Map{
			{
				Type:  GLOBAL_OUTPUT_DESCRIPTOR,
				Key:   key.Bytes(),
				Value: []byte(desc.Descriptor),
			},
		},
	}

	// Write a map for each key.
	for _, k := range desc.Keys {
		var mfpAndPath []byte
		mfpAndPath = binary.BigEndian.AppendUint32(mfpAndPath, k.MasterFingerprint)
		for _, p := range k.Path {
			mfpAndPath = binary.LittleEndian.AppendUint32(mfpAndPath, p)
		}
		f.Key = append(f.Key, psbt.Entry{
			Type:  KEY_XPUB,
			Key:   k.Key,
			Value: mfpAndPath,
		})
	}

	return f, nil
}

func Decode(f File) (OutputDescriptor, error) {
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
		}
	}
	for _, e := range f.Key {
		switch t := e.Type; t {
		case KEY_XPUB:
			k, err := DecodeXPUB(e)
			if err != nil {
				return OutputDescriptor{}, fmt.Errorf("desc: invalid key at index %d: %w", len(desc.Keys), err)
			}
			desc.Keys = append(desc.Keys, k)
		}
	}
	return desc, nil
}
