package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"github.com/joho/godotenv"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"
	"log"
)

const (
	HEADER_LENGTH = 1024
	CONNECT       = 0
	MESSAGE       = 1
	RESPONSE      = 2
	ERROR         = 3
	DISCONNECT    = 4
)

var (
	prime = []byte(os.Getenv("PRIME"))
	base  = big.NewInt(2)
)

type Client struct {
	HostName string
	Host     string
	Port     string
	Socket   net.Conn
	PrivKey  *big.Int
	PubKey   *big.Int
	AESKey   string
}

func CheckError(e error) {
	if e != nil {
		fmt.Println(e)
	}
}

func encrypt(data []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	CheckError(err)
	gcm, err := cipher.NewGCM(block)
	CheckError(err)
	iv := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, iv)
	ciphertext := gcm.Seal(iv, iv, data, nil)
	buf := make([]byte, 5)
	_, err = rand.Read(buf)
	CheckError(err)
	ciphertext = append(buf, ciphertext...)
	return ciphertext
}

func decrypt(ciphertext []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	CheckError(err)
	if len(ciphertext) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := ciphertext[5:17]
	ciphertext = ciphertext[17:]
	gcm, err := cipher.NewGCM(block)
	CheckError(err)
	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
	CheckError(err)
	return plaintext
}

func (c *Client) send(action int, data string) {
	key, _ := hex.DecodeString(c.AESKey)
	encrypted_data := encrypt([]byte(data), key)
	length := fmt.Sprint(len(encrypted_data))
	encrypted_header := encrypt([]byte(fmt.Sprint(action)+length), key)
	buffer := strings.Repeat(" ", HEADER_LENGTH-len(encrypted_header))
	c.Socket.Write([]byte(string(encrypted_header) + buffer + string(encrypted_data)))
}

func (c *Client) receive() (int, string) {
	key, _ := hex.DecodeString(c.AESKey)
	reader := bufio.NewReader(c.Socket)
	header := make([]byte, HEADER_LENGTH)
	reader.Read(header)
	decrypted_header := decrypt([]byte(strings.TrimSpace(string(header))), key)
	action, err := strconv.Atoi(string(decrypted_header[0]))
	CheckError(err)
	length, err := strconv.Atoi(string(decrypted_header[1:]))
	CheckError(err)
	data := make([]byte, length)
	reader.Read(data)
	return action, string(decrypt(data, key))
}

func (c *Client) generatePrivateKey() {
	priv_key := make([]byte, 540)
	_, err := rand.Read(priv_key)
	CheckError(err)
	c.PrivKey = new(big.Int).SetBytes(priv_key)
}

func (c *Client) generatePublicKey() {
	parsed_prime := big.NewInt(0)
	parsed_prime.UnmarshalText(prime)
	var pub_key big.Int
	pub_key.Exp(base, c.PrivKey, parsed_prime)
	c.PubKey = &pub_key
}

func (c *Client) performKeyExchange() {
	key_length := fmt.Sprint(len(c.PubKey.Bytes()))
	buffer := strings.Repeat(" ", HEADER_LENGTH-len(key_length))
	send_header := key_length + buffer
	c.Socket.Write(append([]byte(send_header), c.PubKey.Bytes()...))
	reader := bufio.NewReader(c.Socket)
	header := make([]byte, HEADER_LENGTH)
	reader.Read(header)
	length, err := strconv.Atoi(strings.TrimSpace(string(header)))
	CheckError(err)
	data := make([]byte, length)
	reader.Read(data)
	remote_pub_key := data
	c.getKey(remote_pub_key)
}

func (c *Client) getKey(remote_pub_key []byte) {
	pub_key_int := big.NewInt(0)
	pub_key_int.SetBytes(remote_pub_key)
	parsed_prime := big.NewInt(0)
	parsed_prime.UnmarshalText(prime)
	var shared_secret big.Int
	shared_secret.Exp(pub_key_int, c.PrivKey, parsed_prime)
	hash := sha256.New()
	hash.Write(shared_secret.Bytes())
	md := hash.Sum(nil)
	mdStr := hex.EncodeToString(md)
	c.AESKey = mdStr
	fmt.Println("Key: ", mdStr)
}

func (c *Client) interact() {
	c.generatePrivateKey()
	c.generatePublicKey()
	c.performKeyExchange()
	for {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("\n>> ")
		msg, err := reader.ReadString('\n')
		CheckError(err)
		message := strings.TrimSpace(string(msg))
		if (message == "quit") {
			c.send(DISCONNECT, "")
		}
		c.send(MESSAGE, message)
		action, response := c.receive()
		if (action == DISCONNECT) {
			break
		}
		if (action == RESPONSE) {
			fmt.Println(response)
		}
	}
}

func (c *Client) connect() {
	var err error
	c.Socket, err = net.Dial("tcp", c.Host+":"+c.Port)
	CheckError(err)
	c.interact()
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	name, err := os.Hostname()
	CheckError(err)
	client := Client{
		HostName: name,
		Host:     os.Getenv("HOST"),
		Port:     os.Getenv("PORT"),
	}
	client.connect()
}
