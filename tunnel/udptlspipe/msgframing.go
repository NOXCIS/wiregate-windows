/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2024 AmneziaWG. All Rights Reserved.
 */

package udptlspipe

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

// Message framing constants matching udptlspipe server protocol
const (
	// MaxMessageLength is the maximum length that is safe to use.
	MaxMessageLength = 1320

	// MinMessageLength is the minimum message size. If the message is smaller,
	// it will be padded with random bytes.
	MinMessageLength = 100

	// MaxPaddingLength is the maximum size of a random padding that's added to
	// every message.
	MaxPaddingLength = 256
)

// packMessage wraps data with the udptlspipe framing protocol.
// Message format:
//
//	<2 bytes>: body length (big-endian)
//	<body bytes>
//	<2 bytes>: padding length (big-endian)
//	<random padding bytes>
func packMessage(data []byte) []byte {
	// Calculate padding length
	minLength := MinMessageLength - len(data)
	if minLength <= 0 {
		minLength = 1
	}
	maxLength := MaxPaddingLength
	if maxLength <= minLength {
		maxLength = minLength + 1
	}

	// Generate random padding
	padding := createRandomPadding(minLength, maxLength)

	// Pack: <2 byte len><data><2 byte padding len><padding>
	msg := make([]byte, len(data)+len(padding)+4)
	binary.BigEndian.PutUint16(msg[:2], uint16(len(data)))
	copy(msg[2:], data)
	binary.BigEndian.PutUint16(msg[len(data)+2:len(data)+4], uint16(len(padding)))
	copy(msg[len(data)+4:], padding)

	return msg
}

// unpackMessage extracts data from a message using the udptlspipe framing protocol.
// Returns the original data without the framing overhead.
func unpackMessage(msg []byte) ([]byte, error) {
	if len(msg) < 4 {
		return nil, fmt.Errorf("message too short: %d bytes", len(msg))
	}

	// Read data length
	dataLen := binary.BigEndian.Uint16(msg[:2])
	if int(dataLen)+4 > len(msg) {
		return nil, fmt.Errorf("invalid data length %d for message of %d bytes", dataLen, len(msg))
	}

	// Extract the data (skip the padding)
	data := make([]byte, dataLen)
	copy(data, msg[2:2+dataLen])

	return data, nil
}

// createRandomPadding creates a random padding array with length between min and max.
func createRandomPadding(minLength, maxLength int) []byte {
	// Generate a random length for the slice between minLength and maxLength
	lengthBuf := make([]byte, 1)
	_, err := rand.Read(lengthBuf)
	if err != nil {
		// Fallback to minimum length if random fails
		lengthBuf[0] = 0
	}
	length := int(lengthBuf[0])

	// Ensure the length is within our desired range
	length = (length % (maxLength - minLength)) + minLength

	// Create a slice of the random length
	padding := make([]byte, length)

	// Fill the slice with random bytes
	_, err = rand.Read(padding)
	if err != nil {
		// If random fails, just use zeros (still valid padding)
		for i := range padding {
			padding[i] = 0
		}
	}

	return padding
}
