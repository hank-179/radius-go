package radius

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	codeAccessRequest byte = 1
	codeAccessAccept  byte = 2
	codeAccessReject  byte = 3

	attrUserName     byte = 1
	attrUserPassword byte = 2
	attrReplyMessage byte = 18

	headerLength    = 20
	maxPacketLength = 4096
)

type packet struct {
	Code          byte
	Identifier    byte
	Authenticator [16]byte
	Attributes    []attribute
}

type attribute struct {
	Type  byte
	Value []byte
}

func parsePacket(data []byte) (*packet, error) {
	if len(data) < headerLength {
		return nil, errors.New("packet is shorter than the RADIUS header")
	}
	length := int(binary.BigEndian.Uint16(data[2:4]))
	if length < headerLength {
		return nil, errors.New("packet length is shorter than the RADIUS header")
	}
	if length > maxPacketLength {
		return nil, errors.New("packet exceeds the maximum RADIUS length")
	}
	if length > len(data) {
		return nil, errors.New("packet length exceeds the received datagram")
	}
	data = data[:length]

	pkt := &packet{
		Code:       data[0],
		Identifier: data[1],
	}
	copy(pkt.Authenticator[:], data[4:20])

	for pos := headerLength; pos < length; {
		if pos+2 > length {
			return nil, errors.New("attribute header is truncated")
		}
		attrType := data[pos]
		attrLength := int(data[pos+1])
		if attrLength < 2 {
			return nil, errors.New("attribute length is invalid")
		}
		if pos+attrLength > length {
			return nil, errors.New("attribute exceeds packet length")
		}
		value := make([]byte, attrLength-2)
		copy(value, data[pos+2:pos+attrLength])
		pkt.Attributes = append(pkt.Attributes, attribute{Type: attrType, Value: value})
		pos += attrLength
	}
	return pkt, nil
}

func (p *packet) firstAttribute(attrType byte) ([]byte, bool) {
	for _, attr := range p.Attributes {
		if attr.Type == attrType {
			return attr.Value, true
		}
	}
	return nil, false
}

func buildResponse(code byte, identifier byte, requestAuthenticator [16]byte, secret []byte, attrs []attribute) ([]byte, error) {
	attrBytes, err := encodeAttributes(attrs)
	if err != nil {
		return nil, err
	}
	length := headerLength + len(attrBytes)
	if length > maxPacketLength {
		return nil, errors.New("response exceeds the maximum RADIUS length")
	}

	resp := make([]byte, length)
	resp[0] = code
	resp[1] = identifier
	binary.BigEndian.PutUint16(resp[2:4], uint16(length))
	copy(resp[4:20], requestAuthenticator[:])
	copy(resp[20:], attrBytes)

	hashInput := make([]byte, 0, len(resp)+len(secret))
	hashInput = append(hashInput, resp...)
	hashInput = append(hashInput, secret...)
	authenticator := md5.Sum(hashInput)
	copy(resp[4:20], authenticator[:])

	return resp, nil
}

func encodeAttributes(attrs []attribute) ([]byte, error) {
	var out []byte
	for _, attr := range attrs {
		if len(attr.Value) > 253 {
			return nil, fmt.Errorf("attribute %d is too long", attr.Type)
		}
		out = append(out, attr.Type, byte(len(attr.Value)+2))
		out = append(out, attr.Value...)
	}
	return out, nil
}

func replyMessage(message string) attribute {
	return attribute{Type: attrReplyMessage, Value: []byte(message)}
}

func decryptUserPassword(encrypted []byte, secret []byte, requestAuthenticator [16]byte) (string, error) {
	if len(encrypted) == 0 || len(encrypted)%16 != 0 || len(encrypted) > 128 {
		return "", errors.New("encrypted User-Password length is invalid")
	}

	plain := make([]byte, len(encrypted))
	previous := requestAuthenticator[:]
	for offset := 0; offset < len(encrypted); offset += 16 {
		hashInput := make([]byte, 0, len(secret)+len(previous))
		hashInput = append(hashInput, secret...)
		hashInput = append(hashInput, previous...)
		block := md5.Sum(hashInput)
		for i := 0; i < 16; i++ {
			plain[offset+i] = encrypted[offset+i] ^ block[i]
		}
		previous = encrypted[offset : offset+16]
	}

	if zero := bytes.IndexByte(plain, 0); zero >= 0 {
		for _, b := range plain[zero:] {
			if b != 0 {
				return "", errors.New("User-Password padding is invalid")
			}
		}
		plain = plain[:zero]
	}
	return string(plain), nil
}

func encryptUserPassword(password []byte, secret []byte, requestAuthenticator [16]byte) ([]byte, error) {
	if len(password) > 128 {
		return nil, errors.New("password exceeds the RADIUS limit")
	}
	paddedLength := ((len(password) / 16) + 1) * 16
	if len(password) > 0 && len(password)%16 == 0 {
		paddedLength = len(password) + 16
	}
	if paddedLength > 128 {
		return nil, errors.New("padded password exceeds the RADIUS limit")
	}

	plain := make([]byte, paddedLength)
	copy(plain, password)
	encrypted := make([]byte, paddedLength)
	previous := requestAuthenticator[:]
	for offset := 0; offset < paddedLength; offset += 16 {
		hashInput := make([]byte, 0, len(secret)+len(previous))
		hashInput = append(hashInput, secret...)
		hashInput = append(hashInput, previous...)
		block := md5.Sum(hashInput)
		for i := 0; i < 16; i++ {
			encrypted[offset+i] = plain[offset+i] ^ block[i]
		}
		previous = encrypted[offset : offset+16]
	}
	return encrypted, nil
}

func randomAuthenticator() ([16]byte, error) {
	var authenticator [16]byte
	_, err := rand.Read(authenticator[:])
	return authenticator, err
}
