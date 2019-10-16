package main

import (
	"bufio"
	"fmt"
	"os"

	"./TOTP"
)

func main() {
	// User gets a secret token that is saved on server for
	// that user and on user's device. This does not change
	// and is used for generating OTPs.
	secretToken := TOTP.GenerateSecretToken(24)

	// sample token to be displayed on user's phone
	tOTP := TOTP.GenerateUserOTP(secretToken)
	fmt.Println("HERE is your OTP valid for 30 seconds : ", tOTP)

	// user enters the code for verification
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter OTP : ")
	inputToken, _ := reader.ReadString('\n')

	// remove "\n" from the input token
	inputToken = inputToken[:len(inputToken)-1]

	// server generates the OTPs on its end for
	// current, previous and next time interval
	serverOTPs := TOTP.GenerateServerOTP(secretToken)
	fmt.Println("Verification TOKENS : ", serverOTPs)

	for _, otp := range serverOTPs {
		if otp == inputToken {
			fmt.Println("YES Matched")
			return
		}
	}

	fmt.Println("Oh NO..")
}
