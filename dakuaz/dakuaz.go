package dakuaz

import (
	"crypto"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/cloudflare/circl/sign/ed448"
	"golang.org/x/crypto/blake2b"
)

const tokenSize = 64
const idSize = 32
const classSize = 1
const levelSize = 1
const expireTimeSize = 8
const hashSize = 32
const signatureSize = 114

type Dakuaz struct {
	Token     [tokenSize]byte
	Id        [idSize]byte
	Class     int8
	Level     int8
	ExpireAt  int64
	Hash      [hashSize]byte
	Signature [signatureSize]byte
}

func New(id string, class int8, level int8, duration time.Duration) *Dakuaz {
	d := &Dakuaz{}
	d.Id = blake2b.Sum256([]byte(id))
	d.Class = class
	d.Level = level
	d.ExpireAt = time.Now().Add(duration).Unix()
	return d
}

func (d *Dakuaz) RegisterTokenID(tokenID [64]byte) {
	d.Token = tokenID
}

func (d *Dakuaz) MakeHash() error {
	hash, err := blake2b.New256(nil)
	if err != nil {
		return err
	}
	hash.Write(d.Token[:])
	hash.Write(d.Id[:])
	buf := [8]byte{}
	binary.BigEndian.PutUint64(buf[:], uint64(d.Class))
	hash.Write(buf[:])
	binary.BigEndian.PutUint64(buf[:], uint64(d.Level))
	hash.Write(buf[:])
	binary.BigEndian.PutUint64(buf[:], uint64(d.ExpireAt))
	hash.Write(buf[:])
	d.Hash = blake2b.Sum256(hash.Sum(nil))
	return nil
}

func (d *Dakuaz) MakeSignature(seed [57]byte) error {
	priv := ed448.NewKeyFromSeed(seed[:])
	sign, err := priv.Sign(rand.Reader, d.Hash[:], crypto.Hash(0))
	if err != nil {
		return fmt.Errorf("dakuaz.MakeSignature: %w", err)
	}
	copy(d.Signature[:], sign[:])
	return nil
}

func (d *Dakuaz) Serialize() [tokenSize + idSize + classSize + levelSize + expireTimeSize + hashSize + signatureSize]byte {
	buf := [tokenSize + idSize + classSize + levelSize + expireTimeSize + hashSize + signatureSize]byte{}
	copy(buf[:tokenSize], d.Token[:])
	copy(buf[tokenSize:tokenSize+idSize], d.Id[:])
	buf[tokenSize+idSize] = byte(d.Class)
	buf[tokenSize+idSize+classSize] = byte(d.Level)
	binary.BigEndian.PutUint64(buf[tokenSize+idSize+classSize+levelSize:], uint64(d.ExpireAt))
	copy(buf[tokenSize+idSize+classSize+levelSize+expireTimeSize:tokenSize+idSize+classSize+levelSize+expireTimeSize+hashSize], d.Hash[:])
	copy(buf[tokenSize+idSize+classSize+levelSize+expireTimeSize+hashSize:tokenSize+idSize+classSize+levelSize+expireTimeSize+hashSize+signatureSize], d.Signature[:])
	return buf
}

func Deserialize(buf [tokenSize + idSize + classSize + levelSize + expireTimeSize + hashSize + signatureSize]byte) *Dakuaz {
	d := &Dakuaz{}
	copy(d.Token[:], buf[:tokenSize])
	copy(d.Id[:], buf[tokenSize:tokenSize+idSize])
	d.Class = int8(buf[tokenSize+idSize])
	d.Level = int8(buf[tokenSize+idSize+classSize])
	d.ExpireAt = int64(binary.BigEndian.Uint64(buf[tokenSize+idSize+classSize+levelSize : tokenSize+idSize+classSize+levelSize+expireTimeSize]))
	copy(d.Hash[:], buf[tokenSize+idSize+classSize+levelSize+expireTimeSize:tokenSize+idSize+classSize+levelSize+expireTimeSize+hashSize])
	copy(d.Signature[:], buf[tokenSize+idSize+classSize+levelSize+expireTimeSize+hashSize:tokenSize+idSize+classSize+levelSize+expireTimeSize+hashSize+signatureSize])
	return d
}

func (d *Dakuaz) Verify(key [57]byte) bool {
	priv := ed448.NewKeyFromSeed(key[:])
	hash := d.Hash
	if err := d.MakeHash(); err != nil {
		return false
	}
	if hash != d.Hash {
		return false
	}
	return ed448.Verify(priv.Public().(ed448.PublicKey), d.Hash[:], d.Signature[:], "")
}

func (d *Dakuaz) IsExpired() bool {
	return time.Now().Unix() > d.ExpireAt
}

func (d *Dakuaz) Renew(seed [57]byte, duration time.Duration, class, level int8) error {
	d.ExpireAt = time.Now().Add(duration).Unix()
	d.Level = level
	d.Class = class
	if err := d.MakeHash(); err != nil {
		return fmt.Errorf("dakuaz.Renew: %w", err)
	}
	if err := d.MakeSignature(seed); err != nil {
		return fmt.Errorf("dakuaz.Renew: %w", err)
	}
	return nil
}
