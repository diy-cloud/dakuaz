package dakuaz

import (
	"crypto"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/cloudflare/circl/sign/ed448"
)

const ChunkSize = 64

const HashLevel = 32

const IdSize = HashLevel
const classSize = 4
const levelSize = 4
const expireTimeSize = 8
const boolSize = 1
const SignatureSize = 114
const DakuazSize = IdSize + classSize + levelSize + expireTimeSize + boolSize + SignatureSize

type Dakuaz struct {
	Id        [IdSize]byte
	Class     uint32
	Level     uint32
	ExpireAt  int64
	Echo      bool
	Signature [SignatureSize]byte

	hasher func([]byte) [HashLevel]byte
	hash   [HashLevel]byte
	seed   [57]byte
}

func New(hasher func([]byte) [HashLevel]byte, seed [57]byte, id string, class uint32, level uint32, duration time.Duration, echo bool) *Dakuaz {
	d := &Dakuaz{}
	d.Id = hasher([]byte(id))
	d.Class = class
	d.Level = level
	d.ExpireAt = time.Now().Add(duration).Unix()
	d.Echo = echo

	d.seed = seed
	d.hasher = hasher
	return d
}

func (d *Dakuaz) makeHash() error {
	buf := [IdSize + classSize + levelSize + expireTimeSize + boolSize]byte{}
	copy(buf[:IdSize], d.Id[:])
	binary.BigEndian.PutUint32(buf[IdSize:], uint32(d.Class))
	binary.BigEndian.PutUint32(buf[IdSize+classSize:], uint32(d.Level))
	buf[IdSize+classSize] = byte(d.Level)
	binary.BigEndian.PutUint64(buf[IdSize+classSize+levelSize:], uint64(d.ExpireAt))
	buf[IdSize+classSize+levelSize+expireTimeSize] = byte(0)
	if d.Echo {
		buf[IdSize+classSize+levelSize+expireTimeSize] = byte(1)
	}
	d.hash = d.hasher(buf[:])
	return nil
}

func (d *Dakuaz) makeSignature() error {
	priv := ed448.NewKeyFromSeed(d.seed[:])
	if err := d.makeHash(); err != nil {
		return err
	}
	sign, err := priv.Sign(rand.Reader, d.hash[:], crypto.Hash(0))
	if err != nil {
		return fmt.Errorf("dakuaz.MakeSignature: %w", err)
	}
	copy(d.Signature[:], sign[:])
	return nil
}

func (d *Dakuaz) Serialize() ([IdSize + classSize + levelSize + expireTimeSize + boolSize + SignatureSize]byte, error) {
	buf := [IdSize + classSize + levelSize + expireTimeSize + boolSize + SignatureSize]byte{}
	if err := d.makeSignature(); err != nil {
		return buf, err
	}
	copy(buf[:IdSize], d.Id[:])
	binary.BigEndian.PutUint32(buf[IdSize:], uint32(d.Class))
	binary.BigEndian.PutUint32(buf[IdSize+classSize:], uint32(d.Level))
	binary.BigEndian.PutUint64(buf[IdSize+classSize+levelSize:], uint64(d.ExpireAt))
	buf[IdSize+classSize+levelSize+expireTimeSize] = byte(0)
	if d.Echo {
		buf[IdSize+classSize+levelSize+expireTimeSize] = byte(1)
	}
	copy(buf[IdSize+classSize+levelSize+expireTimeSize+boolSize:IdSize+classSize+levelSize+expireTimeSize+boolSize+SignatureSize], d.Signature[:])
	return buf, nil
}

func Deserialize(buf [IdSize + classSize + levelSize + expireTimeSize + boolSize + SignatureSize]byte) *Dakuaz {
	d := &Dakuaz{}
	copy(d.Id[:], buf[:IdSize])
	d.Class = binary.BigEndian.Uint32(buf[IdSize:])
	d.Level = binary.BigEndian.Uint32(buf[IdSize+classSize:])
	d.ExpireAt = int64(binary.BigEndian.Uint64(buf[IdSize+classSize+levelSize : IdSize+classSize+levelSize+expireTimeSize]))
	d.Echo = false
	if buf[+IdSize+classSize+levelSize+expireTimeSize] == byte(1) {
		d.Echo = true
	}
	copy(d.Signature[:], buf[IdSize+classSize+levelSize+expireTimeSize+boolSize:IdSize+classSize+levelSize+expireTimeSize+boolSize+SignatureSize])
	return d
}

func (d *Dakuaz) Verify(hasher func([]byte) [HashLevel]byte, key [57]byte) bool {
	d.hasher = hasher
	d.seed = key
	priv := ed448.NewKeyFromSeed(key[:])
	if err := d.makeHash(); err != nil {
		return false
	}
	return ed448.Verify(priv.Public().(ed448.PublicKey), d.hash[:], d.Signature[:], "")
}

func (d *Dakuaz) IsExpired() bool {
	return time.Now().Unix() > d.ExpireAt
}
