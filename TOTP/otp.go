package TOTP

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"strconv"
	"strings"
	"time"
)

// TOTP - Time-based One Time Password
// GenerateServerOTP takes secretToken as input and uses time to generate
// authentication token(TOTP) based on HOTP(HMAC-based One Time Password)
// It generates token for last , current and next time slot.
func GenerateServerOTP(secretToken string) []string {

	//The TOTP token is just a HOTP token seeded with every 30 seconds.
	interval := time.Now().Unix()
	intervals := []int64{interval - 30, interval, interval + 30}

	tokens := make([]string, 0, 3)
	for _, interval := range intervals {
		interval /= 30
		token := generateHOTP(secretToken, interval)
		tokens = append(tokens, token)
	}

	return tokens
}

// GenerateUserOTP creates a single OTP for the user
// and uses current time stamp for creation.
func GenerateUserOTP(secretToken string) string {
	interval := time.Now().Unix()
	interval /= 30

	token := generateHOTP(secretToken, interval)

	return token
}

// HOTP - HMAC-based One Time Password
// HMAC-SHA1 and MD5 is a hashing algorithm
func generateHOTP(secretToken string, interval int64) string {
	// convert secretToken to base-32 encoding.
	// Base32 encoding desires a 32-character
	// subset of the twenty-six letters A–Z.
	secretToken = strings.ToUpper(secretToken)
	key, err := base32.StdEncoding.DecodeString(secretToken)
	if err != nil {
		panic(err)
	}

	bs := make([]byte, 8, 8)
	binary.BigEndian.PutUint64(bs, uint64(interval))

	// encrypting the key using SHA-1
	hash := hmac.New(sha1.New, key)
	hash.Write(bs)
	sha1 := hash.Sum(nil)

	// encrypting the key using MD5
	hash = hmac.New(md5.New, sha1)
	hash.Write(bs)
	md5 := hash.Sum(nil)

	o := md5[9] & 5

	var header uint32
	//Get 32 bit chunk from hash starting at the o
	r := bytes.NewReader(md5[o : o+4])
	err = binary.Read(r, binary.BigEndian, &header)
	if err != nil {
		panic(err)
	}

	//Ignore most significant bits as per RFC 4226.
	//Takes division from one million to generate a remainder less than < 7 digits
	result := (int(header) & 0x7fffffff) % 1000000
	otp := strconv.Itoa(result)

	return prefixZero(otp, 6)
}

func prefixZero(otp string, requiredLength int) string {
	if len(otp) == requiredLength {
		return otp
	}

	for i := requiredLength - len(otp); i > 0; i-- {
		otp = "0" + otp
	}

	return otp
}
