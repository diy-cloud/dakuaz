package dakuaz

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/cloudflare/circl/sign/ed448"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20"
)

const ChunkSize = 64

const HashLevel = 32

const IdSize = HashLevel
const classSize = 1
const levelSize = 1
const expireTimeSize = 8
const boolSize = 1
const SignatureSize = 114
const DakuazSize = IdSize + classSize + levelSize + expireTimeSize + boolSize + SignatureSize

type Dakuaz struct {
	Id        [IdSize]byte
	Class     int8
	Level     int8
	ExpireAt  int64
	Echo      bool
	Signature [SignatureSize]byte

	hasher func([]byte) [HashLevel]byte
	hash   [HashLevel]byte
	seed   [57]byte
}

func New(hasher func([]byte) [HashLevel]byte, seed [57]byte, id string, class int8, level int8, duration time.Duration, echo bool) *Dakuaz {
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
	buf[IdSize] = byte(d.Class)
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
	buf[IdSize] = byte(d.Class)
	buf[IdSize+classSize] = byte(d.Level)
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
	d.Class = int8(buf[IdSize])
	d.Level = int8(buf[IdSize+classSize])
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

func Encrypt(data []byte, seed []byte) ([]byte, error) {
	dst := bytes.NewBuffer(nil)
	src := bytes.NewBuffer(data)
	if err := encrypt(src, dst, seed); err != nil {
		return nil, err
	}
	return dst.Bytes(), nil
}

func Decrypt(data []byte, seed []byte) ([DakuazSize]byte, error) {
	dst := bytes.NewBuffer(nil)
	src := bytes.NewBuffer(data)
	if err := decrypt(src, dst, seed); err != nil {
		return [DakuazSize]byte{}, err
	}
	if dst.Len() != DakuazSize {
		return [DakuazSize]byte{}, fmt.Errorf("dakuaz.Decrypt: invalid dakuaz size")
	}
	result := [DakuazSize]byte{}
	copy(result[:], dst.Bytes())
	return result, nil
}

func encrypt(src io.Reader, dst io.Writer, password []byte) error {
	nonce := make([]byte, chacha20.NonceSizeX)
	rand.Read(nonce)
	if _, err := dst.Write(nonce); err != nil {
		return err
	}

	hashed := blake2b.Sum256(password)
	cipher, err := chacha20.NewUnauthenticatedCipher(hashed[:], nonce)
	if err != nil {
		return err
	}

	from := make([]byte, ChunkSize)
	to := make([]byte, ChunkSize)

	for {
		n, err := src.Read(from)
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		cipher.XORKeyStream(to, from[:n])
		if _, err := dst.Write(to[:n]); err != nil {
			return err
		}
	}

	return nil
}

func decrypt(src io.Reader, dst io.Writer, password []byte) error {
	nonce := make([]byte, chacha20.NonceSizeX)
	if _, err := src.Read(nonce); err != nil {
		return err
	}

	hashed := blake2b.Sum256(password)
	cipher, err := chacha20.NewUnauthenticatedCipher(hashed[:], nonce)
	if err != nil {
		return err
	}

	from := make([]byte, ChunkSize)
	to := make([]byte, ChunkSize)

	for {
		n, err := src.Read(from)
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		cipher.XORKeyStream(to, from[:n])
		if _, err := dst.Write(to[:n]); err != nil {
			return err
		}
	}

	return nil
}
