package dakuaz

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20"
)

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
