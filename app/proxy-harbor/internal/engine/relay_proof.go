package engine

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"net"
)

// Optional local relay server proof, before SOCKS5. A fresh 32-byte nonce and
// HMAC authenticate the listener without exposing the key to a replacement.
// This is not a remote node protocol or a substitute for independent rules.
var relayProofMagic = [8]byte{'P', 'H', 'P', '0', 'A', 'U', 'T', 'H'}

func relayProofServer(conn net.Conn, key []byte) error {
	var challenge [40]byte
	if _, err := io.ReadFull(conn, challenge[:]); err != nil {
		return err
	}
	if string(challenge[:8]) != string(relayProofMagic[:]) {
		return errors.New("invalid local relay proof preamble")
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(challenge[:])
	return writeAll(conn, mac.Sum(nil))
}

func relayProofClient(conn net.Conn, key []byte) error {
	var challenge [40]byte
	copy(challenge[:8], relayProofMagic[:])
	if _, err := rand.Read(challenge[8:]); err != nil {
		return err
	}
	if err := writeAll(conn, challenge[:]); err != nil {
		return err
	}
	var response [32]byte
	if _, err := io.ReadFull(conn, response[:]); err != nil {
		return err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(challenge[:])
	if !hmac.Equal(response[:], mac.Sum(nil)) {
		return errors.New("local relay listener proof failed")
	}
	return nil
}
