// Package psbt implements a basic BIP-174 codec.
package psbt

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

type File struct {
	Global []Entry
	Input  []Entry
	Output []Entry
}

const (
	magic                      = "psbt\xff"
	GLOBAL_UNSIGNED_TX KeyType = 0x00
	GLOBAL_XPUB        KeyType = 0x01
)

type KeyType uint64

type ExtendedKey struct {
	MasterFingerprint uint32
	Path              []uint32
	Key               []byte
}

func DecodeXPUB(e Entry) (ExtendedKey, error) {
	if e.Type != GLOBAL_XPUB {
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

type Entry struct {
	Type       KeyType
	Key, Value []byte
}

func Encode(w *bytes.Buffer, f File) {
	w.Write([]byte(magic))
	maps := [][]Entry{f.Global, f.Input, f.Output}
	for _, m := range maps {
		for _, e := range m {
			buf := new(bytes.Buffer)
			EncodeVarUInt(buf, uint64(e.Type))
			EncodeVarUInt(w, uint64(buf.Len()+len(e.Key)))
			w.Write(buf.Bytes())
			w.Write(e.Key)
			EncodeVarUInt(w, uint64(len(e.Value)))
			w.Write(e.Value)
		}
		w.WriteByte(0x00)
	}
}

func EncodeVarUInt(w *bytes.Buffer, v uint64) {
	bo := binary.LittleEndian
	switch {
	case v < 0xfd:
		w.WriteByte(uint8(v))
	case v <= 0xffff:
		var buf [2]uint8
		w.WriteByte(0xfd)
		bo.PutUint16(buf[:], uint16(v))
		w.Write(buf[:])
	case v <= 0xffff_ffff:
		var buf [4]uint8
		w.WriteByte(0xfe)
		bo.PutUint32(buf[:], uint32(v))
		w.Write(buf[:])
	default:
		var buf [8]uint8
		w.WriteByte(0xff)
		bo.PutUint64(buf[:], uint64(v))
		w.Write(buf[:])
	}
}

func Decode(data []byte) (File, int, error) {
	if !bytes.HasPrefix(data, []byte(magic)) {
		return File{}, 0, errors.New("psbt: invalid magic")
	}
	total := len(magic)

	maps := make([][]Entry, 3)
	for i := range maps {
		m, n, err := DecodeMap(data[total:])
		total += n
		if err != nil {
			return File{}, total, fmt.Errorf("psbt: %w", err)
		}
		maps[i] = m
	}
	return File{
		Global: maps[0],
		Input:  maps[1],
		Output: maps[2],
	}, total, nil
}

func DecodeMap(data []byte) ([]Entry, int, error) {
	var m []Entry
	n := 0
	for {
		entry, n1, err := decodeKeyVal(data)
		data = data[n1:]
		n += n1
		if err != nil {
			if errors.Is(err, io.EOF) {
				return m, n, nil
			}
			return nil, n, err
		}
		m = append(m, entry)
	}
}

func decodeKeyVal(data []byte) (Entry, int, error) {
	keyLen, n1, err := DecodeVarUInt(data)
	data = data[n1:]
	if err != nil || keyLen > uint64(len(data)) {
		return Entry{}, 0, io.ErrUnexpectedEOF
	}
	if keyLen == 0 {
		// End of map.
		return Entry{}, n1, io.EOF
	}
	typeAndKey := data[:keyLen]
	typ, typlen, err := DecodeVarUInt(typeAndKey)
	if err != nil {
		return Entry{}, 0, err
	}
	key := typeAndKey[typlen:]
	data = data[keyLen:]
	valLen, n2, err := DecodeVarUInt(data)
	data = data[typlen:]
	if err != nil || valLen > uint64(len(data)) {
		return Entry{}, 0, io.ErrUnexpectedEOF
	}
	val := data[:valLen]
	data = data[valLen:]
	entry := Entry{
		Type:  KeyType(typ),
		Key:   key,
		Value: val,
	}
	return entry, n1 + n2 + int(keyLen+valLen), nil
}

// https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer.
func DecodeVarUInt(data []byte) (uint64, int, error) {
	if len(data) == 0 {
		return 0, 0, io.ErrUnexpectedEOF
	}
	bo := binary.LittleEndian
	switch v := data[0]; v {
	case 0xfd:
		// 16 bit value.
		if len(data) < 3 {
			return 0, 0, io.ErrUnexpectedEOF
		}
		v := bo.Uint16(data[1:])
		return uint64(v), 3, nil
	case 0xfe:
		// 32 bit value.
		if len(data) < 5 {
			return 0, 0, io.ErrUnexpectedEOF
		}
		v := bo.Uint32(data[1:])
		return uint64(v), 5, nil
	case 0xff:
		// 64 bit value.
		if len(data) < 9 {
			return 0, 0, io.ErrUnexpectedEOF
		}
		v := bo.Uint64(data[1:])
		return v, 9, nil
	default:
		// 8 bit value.
		return uint64(v), 1, nil
	}
}
