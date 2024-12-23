package ShuffleGen

import (
	"bytes"
	"fmt"
	"math/rand"
	"testing"
	"time"
)

func GetRandomByte(l int) []byte {
	result := []byte{}
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < l; i++ {
		result = append(result, byte(r.Intn(254)))
	}
	return result
}
func AreBytesEqual(a, b []byte) bool {
	return bytes.Equal(a, b)
}

func TestMain(t *testing.T) {
	data := GetRandomByte((1 << 20) * 20)
	xor := DefaultCipher
	num1, err := xor.Encrypt(data)
	if err != nil {
		panic(err)
	}
	num2, err := xor.Decrypt(num1)
	if err != nil {
		panic(err)
	}
	fmt.Println(len(num2), AreBytesEqual(data, num2))
}

func TestAdd(t *testing.T) {
	fmt.Println(RandomInt64(), RandomInt64(), RandomInt64(), RandomInt64())
	Key := []int64{3978143266212295737, 3559029418170594096, 3689910863560653155, 7075824858527195445}
	data := GetRandomByte((1 << 20) * 20)
	// data := []byte("1231231oiwqetry89q273t42893t4q289etrw89etr82364")
	xor, err := New(Int64SliceToBytes(Key))
	if err != nil {
		panic(err)
	}
	num1, err := xor.Encrypt(data)
	if err != nil {
		panic(err)
	}
	num2, err := xor.Decrypt(num1)
	if err != nil {
		panic(err)
	}
	fmt.Println(len(num2), AreBytesEqual(data, num2))
}
