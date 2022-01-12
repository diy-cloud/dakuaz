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

const TokenSize = 64
const IdSize = 32
const classSize = 1
const levelSize = 1
const expireTimeSize = 8
const HashSize = 32
const SignatureSize = 114
const DakuazSize = TokenSize + IdSize + classSize + levelSize + expireTimeSize + HashSize + SignatureSize

type Dakuaz struct {
	Token     [TokenSize]byte
	Id        [IdSize]byte
	Class     int8
	Level     int8
	ExpireAt  int64
	Hash      [HashSize]byte
	Signature [SignatureSize]byte
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

func (d *Dakuaz) Serialize() [TokenSize + IdSize + classSize + levelSize + expireTimeSize + HashSize + SignatureSize]byte {
	buf := [TokenSize + IdSize + classSize + levelSize + expireTimeSize + HashSize + SignatureSize]byte{}
	copy(buf[:TokenSize], d.Token[:])
	copy(buf[TokenSize:TokenSize+IdSize], d.Id[:])
	buf[TokenSize+IdSize] = byte(d.Class)
	buf[TokenSize+IdSize+classSize] = byte(d.Level)
	binary.BigEndian.PutUint64(buf[TokenSize+IdSize+classSize+levelSize:], uint64(d.ExpireAt))
	copy(buf[TokenSize+IdSize+classSize+levelSize+expireTimeSize:TokenSize+IdSize+classSize+levelSize+expireTimeSize+HashSize], d.Hash[:])
	copy(buf[TokenSize+IdSize+classSize+levelSize+expireTimeSize+HashSize:TokenSize+IdSize+classSize+levelSize+expireTimeSize+HashSize+SignatureSize], d.Signature[:])
	return buf
}

func Deserialize(buf [TokenSize + IdSize + classSize + levelSize + expireTimeSize + HashSize + SignatureSize]byte) *Dakuaz {
	d := &Dakuaz{}
	copy(d.Token[:], buf[:TokenSize])
	copy(d.Id[:], buf[TokenSize:TokenSize+IdSize])
	d.Class = int8(buf[TokenSize+IdSize])
	d.Level = int8(buf[TokenSize+IdSize+classSize])
	d.ExpireAt = int64(binary.BigEndian.Uint64(buf[TokenSize+IdSize+classSize+levelSize : TokenSize+IdSize+classSize+levelSize+expireTimeSize]))
	copy(d.Hash[:], buf[TokenSize+IdSize+classSize+levelSize+expireTimeSize:TokenSize+IdSize+classSize+levelSize+expireTimeSize+HashSize])
	copy(d.Signature[:], buf[TokenSize+IdSize+classSize+levelSize+expireTimeSize+HashSize:TokenSize+IdSize+classSize+levelSize+expireTimeSize+HashSize+SignatureSize])
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
