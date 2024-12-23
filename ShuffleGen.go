package ShuffleGen

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"math"
	"math/big"
)

const iv int64 = 0x114514

var defaultKey []int64 = []int64{1567106914605497586, 3556036468379686064, 3176340012236577404, 1004822329974624625}

var DefaultCipher *Cipher = &Cipher{key: defaultKey}

type Cipher struct {
	key []int64
}

// New Custom pseudo-random algorithm
func New(key []byte) (*Cipher, error) {
	var c Cipher
	if len(key) != 32 {
		return nil, errors.New("the key length is not 32 bits")
	}
	c.key = toLongArray(key)
	return &c, nil
}

// Decrypt 解密
func (a *Cipher) Decrypt(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("insufficient data length")
	}
	num1 := toLongArray(data)
	if len(num1) < 1 {
		return nil, errors.New("insufficient data length")
	}
	num2 := PeDecrypt(num1, a.key)
	num3 := Int64SliceToBytes(num2[1:])
	return TrimTrailingZeros(num3), nil

}

// Encrypt 加密
func (a *Cipher) Encrypt(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("insufficient data length")
	}
	num1 := PadToEightMultiple(data)
	unm2 := toLongArray(num1)
	unm4 := PeEncrypt(append([]int64{RandomInt64()}, unm2...), a.key)
	return Int64SliceToBytes(unm4), nil
}

func TrimTrailingZeros(data []byte) []byte {
	i := len(data) - 1
	for i >= 0 && data[i] == 0 {
		i--
	}
	return data[:i+1]
}

func RandomInt64() int64 {
	newInt := big.NewInt(math.MaxInt64)
	n, err := rand.Int(rand.Reader, newInt)
	if err != nil {
		return 3559029418170594096
	}
	return n.Int64()
}

func Int64SliceToBytes(data []int64) []byte {
	result := make([]byte, len(data)*8)
	for i, num := range data {
		binary.LittleEndian.PutUint64(result[i*8:], uint64(num))
	}
	return result
}

func PadToEightMultiple(data []byte) []byte {
	length := len(data)
	if length%8 == 0 {
		return data
	}
	newLength := length + 8 - length%8
	paddedData := make([]byte, newLength)
	copy(paddedData, data)
	return paddedData
}

func toLongArray(b []byte) []int64 {
	num := (len(b) + 7) / 8
	arr := make([]int64, num)
	for i := 0; i < num-1; i++ {
		arr[i] = int64(binary.LittleEndian.Uint64(b[i*8:]))
	}
	lastBytes := make([]byte, 8)
	copy(lastBytes, b[(num-1)*8:])
	arr[num-1] = int64(binary.LittleEndian.Uint64(lastBytes))
	return arr
}

func PeDecrypt(fdc, fdd []int64) []int64 {
	num := len(fdc)
	if num < 1 {
		return fdc
	}
	num2 := fdc[num-1]
	num3 := fdc[0]
	num4 := int64(6 + 52/num)
	for num5 := num4 * iv; num5 != 0; num5 -= iv {
		num6 := num5 >> 2 & 3
		var num7 int64
		for num7 = int64(num - 1); num7 > 0; num7-- {
			num2 = fdc[num7-1]
			fdc[num7] -= (num2>>5 ^ num3<<2) + (num3>>3 ^ num2<<4) ^ ((num5 ^ num3) + (fdd[(num7&3^num6)] ^ num2))
			num3 = fdc[num7]
		}
		num2 = fdc[num-1]
		fdc[0] -= (num2>>5 ^ num3<<2) + (num3>>3 ^ num2<<4) ^ ((num5 ^ num3) + (fdd[(num7&3^num6)] ^ num2))
		num3 = fdc[0]
	}
	return fdc
}

func PeEncrypt(fda []int64, fdb []int64) []int64 {
	num := len(fda)
	if num < 1 {
		return fda
	}
	num2 := fda[num-1]
	num3 := fda[0]
	num4 := int64(0)
	num5 := int64(6 + 52/num)
	for ; num5 > 0; num5-- {
		num4 += iv
		num7 := (num4 >> 2) & 3
		var num8 int64
		for num8 = 0; num8 < int64(num-1); num8++ {
			num3 = fda[num8+1]
			fda[num8] += (num2>>5 ^ num3<<2) + (num3>>3 ^ num2<<4) ^ ((num4 ^ num3) + (fdb[(num8&3)^num7] ^ num2))
			num2 = fda[num8]
		}
		num3 = fda[0]
		fda[num-1] += (num2>>5 ^ num3<<2) + (num3>>3 ^ num2<<4) ^ ((num4 ^ num3) + (fdb[(num8&3)^num7] ^ num2))
		num2 = fda[num-1]
	}
	return fda
}
