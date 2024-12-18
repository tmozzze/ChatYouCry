package algorithm

import (
	"encoding/binary"
	"errors"
	"fmt"
)

type Magenta struct {
	S []uint64 // Расширенный ключ
	r int      // Количество раундов
	w uint     // Размер слова в битах
	b int      // Длина ключа в байтах
}

func NewMagenta() *Magenta {
	return &Magenta{
		r: 12, // Количество раундов
		w: 64, // Размер слова в битах (16, 32, 64)
		b: 16, // Длина ключа в байтах
	}
}

// SetKey устанавливает ключ и выполняет расширение ключа
func (m *Magenta) SetKey(key []byte) error {
	if len(key) == 0 {
		return errors.New("key cannot be empty")
	}
	m.b = len(key)
	m.S = m.keyExpansion(key)
	return nil
}

func (m *Magenta) Encrypt(data []byte) ([]byte, error) {
	blockSize := m.w / 4 // Размер блока в байтах
	if len(data)%int(blockSize) != 0 {
		return nil, fmt.Errorf("data length (%d) is not a multiple of block size (%d)", len(data), blockSize)
	}

	encrypted := make([]byte, len(data))
	for i := 0; i < len(data); i += int(blockSize) {
		block, err := m.encryptBlock(data[i : i+int(blockSize)])
		if err != nil {
			return nil, err
		}
		copy(encrypted[i:i+int(blockSize)], block)
	}

	return encrypted, nil
}

func (m *Magenta) Decrypt(data []byte) ([]byte, error) {
	blockSize := m.w / 4 // Размер блока в байтах
	if len(data)%int(blockSize) != 0 {
		return nil, fmt.Errorf("data length (%d) is not a multiple of block size (%d)", len(data), blockSize)
	}

	decrypted := make([]byte, len(data))
	for i := 0; i < len(data); i += int(blockSize) {
		block, err := m.decryptBlock(data[i : i+int(blockSize)])
		if err != nil {
			return nil, err
		}
		copy(decrypted[i:i+int(blockSize)], block)
	}

	return decrypted, nil
}

func (m *Magenta) encryptBlock(block []byte) ([]byte, error) {
	wordSizeBytes := m.w / 8 // Размер слова в байтах
	if len(block) != int(wordSizeBytes*2) {
		return nil, fmt.Errorf("block size must be %d bytes", wordSizeBytes*2)
	}

	A := binary.LittleEndian.Uint64(block[0:8])
	B := binary.LittleEndian.Uint64(block[8:16])

	for i := 0; i < m.r; i++ {
		A = m.sbox(A) ^ m.S[i%len(m.S)] ^ B
		B = m.hadamard(B) ^ A
	}

	encryptedBlock := make([]byte, wordSizeBytes*2)
	binary.LittleEndian.PutUint64(encryptedBlock[0:8], A)
	binary.LittleEndian.PutUint64(encryptedBlock[8:16], B)
	return encryptedBlock, nil
}

func (m *Magenta) decryptBlock(block []byte) ([]byte, error) {
	wordSizeBytes := m.w / 8 // Размер слова в байтах
	if len(block) != int(wordSizeBytes*2) {
		return nil, fmt.Errorf("block size must be %d bytes", wordSizeBytes*2)
	}

	A := binary.LittleEndian.Uint64(block[0:8])
	B := binary.LittleEndian.Uint64(block[8:16])

	for i := m.r - 1; i >= 0; i-- {
		B = m.invHadamard(B) ^ A
		A = m.invSbox(A ^ m.S[i%len(m.S)] ^ B)
	}

	decryptedBlock := make([]byte, wordSizeBytes*2)
	binary.LittleEndian.PutUint64(decryptedBlock[0:8], A)
	binary.LittleEndian.PutUint64(decryptedBlock[8:16], B)
	return decryptedBlock, nil
}

// keyExpansion расширяет ключ на основе длины ключа
func (m *Magenta) keyExpansion(key []byte) []uint64 {
	size := 2 * (m.r + 1)
	S := make([]uint64, size)
	for i := 0; i < size; i++ {
		S[i] = uint64(i)<<32 | uint64(key[i%len(key)])
	}
	return S
}

// sbox выполняет S-блок функции
func (m *Magenta) sbox(x uint64) uint64 {
	return ((x << 3) & 0xFFFFFFFFFFFFFFFF) ^ ((x >> 2) & 0xFFFFFFFFFFFFFFFF)
}

// invSbox выполняет обратное преобразование S-блока
func (m *Magenta) invSbox(x uint64) uint64 {
	return ((x >> 3) & 0xFFFFFFFFFFFFFFFF) ^ ((x << 2) & 0xFFFFFFFFFFFFFFFF)
}

// hadamard выполняет Адамарово преобразование
func (m *Magenta) hadamard(x uint64) uint64 {
	return (x ^ (x >> 1)) & 0xFFFFFFFFFFFFFFFF
}

// invHadamard выполняет обратное Адамарово преобразование
func (m *Magenta) invHadamard(x uint64) uint64 {
	return (x ^ (x << 1)) & 0xFFFFFFFFFFFFFFFF
}
