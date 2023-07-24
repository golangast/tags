package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/labstack/gommon/log"
	"golang.org/x/crypto/scrypt"
)

func main() {
	e := echo.New()

	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"*"},
		AllowMethods: []string{http.MethodGet, http.MethodHead, http.MethodPut, http.MethodPatch, http.MethodPost, http.MethodDelete},
	}))

	Routes(e)

	// Route
	e.Logger.SetLevel(log.ERROR)
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.SecureWithConfig(middleware.SecureConfig{
		XSSProtection:      "1; mode=block",
		ContentTypeNosniff: "nosniff",
		//XFrameOptions:         "SAMEORIGIN",
		HSTSMaxAge:            3600,
		ContentSecurityPolicy: "",
	}))
	e.Use(middleware.BodyLimit("3M"))
	e.IPExtractor = echo.ExtractIPDirect()
	e.Use(middleware.GzipWithConfig(middleware.GzipConfig{
		Level: 5,
	}))
	e.Use(middleware.RateLimiter(middleware.NewRateLimiterMemoryStore(30)))
	e.Logger.Fatal(e.Start(":5001"))

}

func Routes(e *echo.Echo) {
	e.POST("/p", posts)
	e.GET("/g", gets)

}

func posts(c echo.Context) error {

	u := new(User)
	if err := c.Bind(&u); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError)
	}

	return c.JSON(http.StatusOK, u)

}
func gets(c echo.Context) error {

	k := Keyen()
	fmt.Println(k)
	cipherkeys, err := Encrypt(k, []byte("privatekey"))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("cipherkeys: %s\n", hex.EncodeToString(cipherkeys))
	cipherkey, err := Encrypt(k, []byte("james@yahoo.com"))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("cipherkeys: %s\n", hex.EncodeToString(cipherkey))

	u := User{
		PK:   k,
		Ekey: cipherkeys,
		Key:  cipherkey,
	}

	byteInfo, err := json.Marshal(u) // has two values returned
	// check if there was an error returned first
	if err != nil {
		fmt.Println(err)
		// handle your error here
	}

	// error here
	req, err := http.Post("https://6862-2601-244-5680-115b-81c0-8ad-cfe0-4840.ngrok.io/p", "application/json", bytes.NewBuffer(byteInfo))

	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(req.Body, req.Header)
	defer req.Body.Close()

	var res map[string]interface{}

	json.NewDecoder(req.Body).Decode(&res)

	fmt.Println("after:", res["json"])

	return c.JSON(http.StatusOK, byteInfo)

}

type User struct {
	PK   []byte `json:"pk" validate:"required"`
	Ekey []byte `json:"ekey" validate:"required"`
	Key  []byte `json:"key" validate:"required"`
}

func Encrypt(key, data []byte) ([]byte, error) {
	key, salt, err := DeriveKey(key, nil)
	if err != nil {
		return nil, err
	}

	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)

	ciphertext = append(ciphertext, salt...)

	return ciphertext, nil
}

func Decrypt(key, data []byte) ([]byte, error) {
	salt, data := data[len(data)-32:], data[:len(data)-32]

	key, _, err := DeriveKey(key, salt)
	if err != nil {
		return nil, err
	}

	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, err
	}

	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func DeriveKey(password, salt []byte) ([]byte, []byte, error) {
	if salt == nil {
		salt = make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			return nil, nil, err
		}
	}

	key, err := scrypt.Key(password, salt, 1048576, 8, 1, 32)
	if err != nil {
		return nil, nil, err
	}

	return key, salt, nil
}
func Keyen() []byte {
	bytes := make([]byte, 64) //generate a random 32 byte key for AES-256
	if _, err := rand.Read(bytes); err != nil {
		panic(err.Error())
	}
	return bytes
}
