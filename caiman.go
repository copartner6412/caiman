package caiman

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"io"
	"reflect"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/copartner6412/input/validate"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/sha3"
	"golang.org/x/term"
)

var (
	ErrPasswordMismatch   = errors.New("passwords do not match")
	ErrCipherTextTooShort = errors.New("cipher text too short")
	ErrMasterKeyNotSet    = errors.New("master key not set")
	ErrWeakPassword       = errors.New("weak password")
	ErrWrongPassword      = errors.New("wrong password")
)

type KDF string

const (
	Argon2id KDF = "Argon2id"
	Argon2i  KDF = "Argon2i"
	PBKDF2   KDF = "PBKDF2"
	HKDF     KDF = "HKDF"
)

type AES string

const (
	AES128 AES = "AES-128"
	AES192 AES = "AES-192"
	AES256 AES = "AES-256"
)

func (a AES) KeyLength() int {
	switch a {
	case AES128:
		return 16
	case AES192:
		return 24
	case AES256:
		return 32
	default:
		return 32
	}
}

type Hash string

const (
	SHA1     Hash = "SHA1"
	SHA2_224 Hash = "SHA2-224"
	SHA2_256 Hash = "SHA2-256"
	SHA2_384 Hash = "SHA2-384"
	SHA2_512 Hash = "SHA2-512"
	SHA3_224 Hash = "SHA3-224"
	SHA3_256 Hash = "SHA3-256"
	SHA3_384 Hash = "SHA3-384"
	SHA3_512 Hash = "SHA3-512"
)

func HashBytes(data []byte, h Hash) []byte {
	var hasher hash.Hash

	switch h {
	case SHA1:
		hasher = sha1.New()
	case SHA2_224:
		hasher = sha256.New224()
	case SHA2_256:
		hasher = sha256.New()
	case SHA2_384:
		hasher = sha512.New384()
	case SHA2_512:
		hasher = sha512.New()
	case SHA3_224:
		hasher = sha3.New224()
	case SHA3_256:
		hasher = sha3.New256()
	case SHA3_384:
		hasher = sha3.New384()
	case SHA3_512:
		hasher = sha3.New512()
	default:
		return nil
	}

	hasher.Write(data)
	return hasher.Sum(nil)
}

func HashString(data string, h Hash) string {
	var hasher hash.Hash

	switch h {
	case SHA1:
		hasher = sha1.New()
	case SHA2_224:
		hasher = sha256.New224()
	case SHA2_256:
		hasher = sha256.New()
	case SHA2_384:
		hasher = sha512.New384()
	case SHA2_512:
		hasher = sha512.New()
	case SHA3_224:
		hasher = sha3.New224()
	case SHA3_256:
		hasher = sha3.New256()
	case SHA3_384:
		hasher = sha3.New384()
	case SHA3_512:
		hasher = sha3.New512()
	default:
		return ""
	}

	hasher.Write([]byte(data))
	return string(hasher.Sum(nil))
}

func (h Hash) HashFunc() func() hash.Hash {
	switch h {
	case SHA1:
		return sha1.New
	case SHA2_224:
		return sha256.New224
	case SHA2_256:
		return sha256.New
	case SHA2_384:
		return sha512.New384
	case SHA2_512:
		return sha512.New
	case SHA3_224:
		return sha3.New224
	case SHA3_256:
		return sha3.New256
	case SHA3_384:
		return sha3.New384
	case SHA3_512:
		return sha3.New512
	default:
		return nil
	}
}

func hashFuncToHash(f func() hash.Hash) Hash {
	fPtr := reflect.ValueOf(f).Pointer()

	switch {
	case fPtr == reflect.ValueOf(sha1.New).Pointer():
		return SHA1
	case fPtr == reflect.ValueOf(sha256.New224).Pointer():
		return SHA2_224
	case fPtr == reflect.ValueOf(sha256.New).Pointer():
		return SHA2_256
	case fPtr == reflect.ValueOf(sha512.New384).Pointer():
		return SHA2_384
	case fPtr == reflect.ValueOf(sha512.New).Pointer():
		return SHA2_512
	case fPtr == reflect.ValueOf(sha3.New224).Pointer():
		return SHA3_224
	case fPtr == reflect.ValueOf(sha3.New256).Pointer():
		return SHA3_256
	case fPtr == reflect.ValueOf(sha3.New384).Pointer():
		return SHA3_384
	case fPtr == reflect.ValueOf(sha3.New512).Pointer():
		return SHA3_512
	default:
		return ""
	}
}

type Prompts struct {
	SetPassword1, SetPassword2, VerifyPassword string
}

type PasswordPolicy struct {
	MinLength                int
	MaxLength                int
	RequiresLower            bool
	RequiresUpper            bool
	RequiresDigit            bool
	RequiresSpecialCharacter bool
}

type argon2Parameters struct {
	memory     uint32
	iterations uint32
	thread     uint8
}

type pbkdf2Parameters struct {
	iterations int
	hash       func() hash.Hash
}

type hkdfParameters struct {
	hash func() hash.Hash
	info []byte
}

type kdfParameters struct {
	kdfAlgorithm        KDF
	encryptionAlgorithm AES
	argon2id            argon2Parameters
	argon2i             argon2Parameters
	pbkdf2              pbkdf2Parameters
	hkdf                hkdfParameters
}

var defaultKDFParameters = kdfParameters{
	kdfAlgorithm:        Argon2id,
	encryptionAlgorithm: AES256,
	argon2id: argon2Parameters{
		memory:     64 * 1024,
		iterations: 1,
		thread:     uint8(runtime.NumCPU()),
	},
	argon2i: argon2Parameters{
		memory:     32 * 1024,
		iterations: 3,
		thread:     uint8(runtime.NumCPU()),
	},
	pbkdf2: pbkdf2Parameters{
		iterations: 2000,
		hash:       sha3.New512,
	},
	hkdf: hkdfParameters{
		hash: sha3.New512,
	},
}

type cryptSettings struct {
	delay               time.Duration
	encryptionAlgorithm AES
	saltLength          int
	prompts             Prompts
	passwordPolicy      PasswordPolicy
}

type secureBytes struct {
	data []byte
}

func newSecureBytes(data []byte) (*secureBytes, error) {
	secure := &secureBytes{
		data: make([]byte, len(data)),
	}
	if err := syscall.Mlock(secure.data); err != nil {
		return nil, fmt.Errorf("error locking memory for secure data: %v", err)
	}
	subtle.ConstantTimeCopy(1, secure.data, data)
	runtime.SetFinalizer(secure, (*secureBytes).clear)
	return secure, nil
}

func (s *secureBytes) clear() {
	for i := range s.data {
		s.data[i] = 0
	}
	_ = syscall.Munlock(s.data)
	s.data = nil
}

type crypt struct {
	settings  *cryptSettings
	masterKey *secureBytes
	sync.RWMutex
}

func (k *crypt) setSettings(s *cryptSettings) {
	k.Lock()
	k.settings = s
	k.Unlock()
}

func (k *crypt) getSettings() *cryptSettings {
	k.RLock()
	defer k.RUnlock()
	return k.settings
}

type Crypt struct {
	*crypt
}

type CryptOption func(*cryptSettings)

func NewCrypt(options ...CryptOption) *Crypt {
	newCrypt := &crypt{
		settings: defaultCryptSettings,
	}

	for _, option := range options {
		option(newCrypt.settings)
	}

	return &Crypt{
		crypt: newCrypt,
	}
}

func SetDefault(c *Crypt) {
	defaultCrypt.setSettings(c.getSettings())
}

var defaultCryptSettings *cryptSettings = &cryptSettings{
	delay:               1,
	encryptionAlgorithm: AES256,
	saltLength:          16,
	prompts: Prompts{
		SetPassword1:   "Enter new password: ",
		SetPassword2:   "Confirm password: ",
		VerifyPassword: "Enter current password: ",
	},
	passwordPolicy: PasswordPolicy{
		MinLength:                8,
		MaxLength:                128,
		RequiresLower:            true,
		RequiresUpper:            false,
		RequiresDigit:            true,
		RequiresSpecialCharacter: false,
	},
}

var defaultCrypt *crypt = &crypt{
	settings: defaultCryptSettings,
}

func WithDelay(delay time.Duration) CryptOption {
	return func(cs *cryptSettings) {
		cs.delay = delay
	}

}

func WithMasterKeyEncryptionAlgorithm(algorithm AES) CryptOption {
	return func(cs *cryptSettings) {
		cs.encryptionAlgorithm = algorithm
	}
}

func WithSaltLength(length int) CryptOption {
	return func(cs *cryptSettings) {
		cs.saltLength = length
	}
}

func WithPrompts(prompts Prompts) CryptOption {
	return func(cs *cryptSettings) {
		cs.prompts = prompts
	}
}

func WithPasswordPolicy(policy PasswordPolicy) CryptOption {
	return func(cs *cryptSettings) {
		cs.passwordPolicy = policy
	}
}

type KDFOption func(*kdfParameters)

func WithKDFAlgorithm(algorithm KDF) KDFOption {
	return func(p *kdfParameters) {
		p.kdfAlgorithm = algorithm
	}
}

func WithMemorySize(size int) KDFOption {
	return func(p *kdfParameters) {
		p.argon2id.memory = uint32(size)
		p.argon2i.memory = uint32(size)
	}
}

func WithIterations(iterations int) KDFOption {
	return func(p *kdfParameters) {
		p.argon2id.iterations = uint32(iterations)
		p.argon2i.iterations = uint32(iterations)
		p.pbkdf2.iterations = iterations
	}
}

func WithParallelism(threadNumber int) KDFOption {
	return func(p *kdfParameters) {
		p.argon2id.thread = uint8(threadNumber)
		p.argon2i.thread = uint8(threadNumber)
	}
}

func WithEncryptionAlgorithm(algorithm AES) KDFOption {
	return func(p *kdfParameters) {
		p.encryptionAlgorithm = algorithm
	}
}

func WithHash(h Hash) KDFOption {
	var hashFunc func() hash.Hash
	switch h {
	case SHA1:
		hashFunc = sha1.New
	case SHA2_224:
		hashFunc = sha256.New224
	case SHA2_256:
		hashFunc = sha256.New
	case SHA2_384:
		hashFunc = sha512.New384
	case SHA2_512:
		hashFunc = sha512.New
	case SHA3_224:
		hashFunc = sha3.New224
	case SHA3_256:
		hashFunc = sha3.New256
	case SHA3_384:
		hashFunc = sha3.New384
	case SHA3_512:
		hashFunc = sha3.New512
	}
	return func(p *kdfParameters) {
		p.pbkdf2.hash = hashFunc
		p.hkdf.hash = hashFunc
	}
}

func WithInfo(info string) KDFOption {
	return func(p *kdfParameters) {
		p.hkdf.info = []byte(info)
	}
}

func (c *Crypt) SetMasterKey(masterKey []byte) {
	c.masterKey, _ = newSecureBytes(masterKey)
}

func SetMasterKey(masterKey []byte) {
	defaultCrypt.masterKey, _ = newSecureBytes(masterKey)
}

func deriveKey(derivedKey *secureBytes, password, rawSalt []byte, parameters kdfParameters) error {
	switch parameters.kdfAlgorithm {
	case Argon2id:
		derivedKey.data = argon2.IDKey(
			password,
			rawSalt,
			parameters.argon2id.iterations,
			parameters.argon2id.memory,
			parameters.argon2id.thread,
			uint32(parameters.encryptionAlgorithm.KeyLength()),
		)
	case Argon2i:
		derivedKey.data = argon2.Key(
			password,
			rawSalt,
			parameters.argon2i.iterations,
			parameters.argon2i.memory,
			parameters.argon2i.thread,
			uint32(parameters.encryptionAlgorithm.KeyLength()),
		)
	case PBKDF2:
		derivedKey.data = pbkdf2.Key(
			password,
			rawSalt,
			parameters.pbkdf2.iterations,
			int(parameters.encryptionAlgorithm.KeyLength()),
			parameters.pbkdf2.hash,
		)
	case HKDF:
		kdf := hkdf.New(
			parameters.hkdf.hash,
			password,
			rawSalt,
			parameters.hkdf.info,
		)

		derivedKey.data = make([]byte, parameters.encryptionAlgorithm.KeyLength())
		if _, err := io.ReadFull(kdf, derivedKey.data); err != nil {
			return fmt.Errorf("error reading bytes from HKDF reader into derived key: %w", err)
		}
	default:
		return fmt.Errorf("unexpected caiman.KDF %#v", parameters.kdfAlgorithm)
	}

	return nil
}

type KeySlot struct {
	EncryptedMasterKey  string         `json:"encrypted_master_key"`
	Salt                string         `json:"salt"`
	KDFAlgorithm        string         `json:"kdf_algorithm"`
	EncryptionAlgorithm string         `json:"encryption_algorithm"`
	KDFParameters       map[string]any `json:"kdf_parameters"`
}

func SetPassword(options ...KDFOption) (KeySlot, error) {
	return defaultCrypt.setPassword(options...)
}

func (c *Crypt) SetPassword(options ...KDFOption) (KeySlot, error) {
	return c.setPassword(options...)
}

func (c *crypt) setPassword(options ...KDFOption) (KeySlot, error) {
	var prompt1, prompt2 string

	settings := *c.getSettings()

	if settings.prompts.SetPassword1 == "" {
		prompt1 = defaultCryptSettings.prompts.SetPassword1
	} else {
		prompt1 = settings.prompts.SetPassword1
	}

	if settings.prompts.SetPassword2 == "" {
		prompt2 = defaultCryptSettings.prompts.SetPassword2
	} else {
		prompt2 = settings.prompts.SetPassword2
	}

	fmt.Print(prompt1)
	password, err := term.ReadPassword(syscall.Stdin)
	if err != nil {
		return KeySlot{}, fmt.Errorf("error reading password: %w", err)

	}
	fmt.Println()

	if err := validate.Password(
		string(password),
		uint(settings.passwordPolicy.MinLength),
		uint(settings.passwordPolicy.MaxLength),
		settings.passwordPolicy.RequiresLower,
		settings.passwordPolicy.RequiresUpper,
		settings.passwordPolicy.RequiresDigit,
		settings.passwordPolicy.RequiresSpecialCharacter,
	); err != nil {
		return KeySlot{}, fmt.Errorf("%w: %w", ErrWeakPassword, err)
	}

	fmt.Print(prompt2)
	confirmPassword, err := term.ReadPassword(syscall.Stdin)
	if err != nil {
		return KeySlot{}, fmt.Errorf("error reading confirm password: %w", err)

	}
	fmt.Println()

	if subtle.ConstantTimeCompare(password, confirmPassword) == 0 {
		return KeySlot{}, ErrPasswordMismatch
	}

	rawSalt := make([]byte, settings.saltLength)
	if _, err := rand.Read(rawSalt); err != nil {
		return KeySlot{}, fmt.Errorf("error creating a random salt: %w", err)
	}

	derivedKey, err := newSecureBytes([]byte{})
	if err != nil {
		return KeySlot{}, fmt.Errorf("error creating a secure memory allocation for derived key: %w", err)
	}

	parameters := defaultKDFParameters

	for _, option := range options {
		option(&parameters)
	}

	if err := deriveKey(derivedKey, password, rawSalt, parameters); err != nil {
		return KeySlot{}, err
	}

	var encryptedMasterKeyBytes []byte

	if c.masterKey == nil {
		rawMasterKey, err := newSecureBytes(make([]byte, settings.encryptionAlgorithm.KeyLength()))
		if err != nil {
			return KeySlot{}, fmt.Errorf("error creating a secure memory allocation for master key: %w", err)
		}

		if _, err := rand.Read(rawMasterKey.data); err != nil {
			return KeySlot{}, fmt.Errorf("error creating a random master key: %w", err)
		}

		encryptedMasterKeyBytes, err = encrypt(rawMasterKey.data, derivedKey.data)
		if err != nil {
			return KeySlot{}, fmt.Errorf("error encrypting the master key using the derived key: %w", err)
		}

		c.masterKey = rawMasterKey
	} else {
		encryptedMasterKeyBytes, err = encrypt(c.masterKey.data, derivedKey.data)
		if err != nil {
			return KeySlot{}, fmt.Errorf("error encrypting the master key using the derived key: %w", err)
		}
	}

	parametersMap := make(map[string]any)

	switch parameters.kdfAlgorithm {
	case Argon2id:
		parametersMap["Memory size"] = int(parameters.argon2id.memory)
		parametersMap["Iterations"] = int(parameters.argon2id.iterations)
		parametersMap["Thread"] = int(parameters.argon2id.thread)
	case Argon2i:
		parametersMap["Memory size"] = int(parameters.argon2i.memory)
		parametersMap["Iterations"] = int(parameters.argon2i.iterations)
		parametersMap["Thread"] = int(parameters.argon2i.thread)
	case PBKDF2:
		parametersMap["Hash function"] = string(hashFuncToHash(parameters.pbkdf2.hash))
		parametersMap["Iterations"] = parameters.pbkdf2.iterations
	case HKDF:
		parametersMap["Hash function"] = string(hashFuncToHash(parameters.hkdf.hash))
		parametersMap["Info"] = string(parameters.hkdf.info)
	default:
		return KeySlot{}, fmt.Errorf("unexpected caiman.KDF: %#v", parameters.kdfAlgorithm)
	}
	parametersMap["Encryption algorithm"] = string(parameters.encryptionAlgorithm)

	return KeySlot{
		EncryptedMasterKey:  base64.StdEncoding.EncodeToString(encryptedMasterKeyBytes),
		Salt:                base64.StdEncoding.EncodeToString(rawSalt),
		KDFAlgorithm:        string(parameters.kdfAlgorithm),
		EncryptionAlgorithm: string(parameters.encryptionAlgorithm),
		KDFParameters:       parametersMap,
	}, nil

}

func VerifyPassword(keySlot KeySlot) error {
	return defaultCrypt.verifyPassword(keySlot)
}

func (c *Crypt) VerifyPassword(keySlot KeySlot) error {
	return c.verifyPassword(keySlot)
}

func (c *crypt) verifyPassword(keySlot KeySlot) error {
	var prompt string

	settings := *c.getSettings()

	if settings.prompts.VerifyPassword == "" {
		prompt = defaultCryptSettings.prompts.VerifyPassword
	} else {
		prompt = settings.prompts.VerifyPassword
	}

	fmt.Print(prompt)
	password, err := term.ReadPassword(syscall.Stdin)
	if err != nil {
		return fmt.Errorf("error reading password: %w", err)

	}
	fmt.Println()

	rawSalt, err := base64.StdEncoding.DecodeString(keySlot.Salt)
	if err != nil {
		return fmt.Errorf("error decoding base64-encoded salt: %w", err)
	}

	derivedKey, err := newSecureBytes([]byte{})
	if err != nil {
		return fmt.Errorf("error creating a secure memory allocation for derived key: %w", err)
	}

	var parameters kdfParameters
	parameters.kdfAlgorithm = KDF(keySlot.KDFAlgorithm)
	parameters.encryptionAlgorithm = AES(keySlot.KDFParameters["Encryption algorithm"].(string))

	switch parameters.kdfAlgorithm {
	case Argon2id:
		parameters.argon2id.memory = uint32(keySlot.KDFParameters["Memory size"].(int))
		parameters.argon2id.iterations = uint32(keySlot.KDFParameters["Iterations"].(int))
		parameters.argon2id.thread = uint8(keySlot.KDFParameters["Thread"].(int))
	case Argon2i:
		parameters.argon2i.memory = uint32(keySlot.KDFParameters["Memory size"].(int))
		parameters.argon2i.iterations = uint32(keySlot.KDFParameters["Iterations"].(int))
		parameters.argon2i.thread = uint8(keySlot.KDFParameters["Thread"].(int))
	case PBKDF2:
		parameters.pbkdf2.iterations = keySlot.KDFParameters["Iterations"].(int)
		parameters.pbkdf2.hash = Hash(keySlot.KDFParameters["Hash function"].(string)).HashFunc()
	case HKDF:
		parameters.hkdf.hash = Hash(keySlot.KDFParameters["Hash function"].(string)).HashFunc()
		parameters.hkdf.info = []byte(keySlot.KDFParameters["Info"].(string))
	default:
		return fmt.Errorf("unexpected caiman.KDF: %#v", keySlot.KDFAlgorithm)
	}

	if err := deriveKey(derivedKey, password, rawSalt, parameters); err != nil {
		return err
	}

	encryptedMasterKeyBytes, err := base64.StdEncoding.DecodeString(keySlot.EncryptedMasterKey)
	if err != nil {
		return fmt.Errorf("error decoding base64-encoded encrypted master key: %w", err)
	}

	rawMasterKey, err := newSecureBytes(make([]byte, settings.encryptionAlgorithm.KeyLength()))
	if err != nil {
		return fmt.Errorf("error creating a secure memory allocation for master key: %w", err)
	}

	rawMasterKey.data, err = decrypt(encryptedMasterKeyBytes, derivedKey.data)
	if err != nil {
		time.Sleep(settings.delay)
		return ErrWrongPassword
	}

	if c.masterKey == nil {
		c.masterKey = rawMasterKey
	}

	return nil
}

func UpdatePassword(oldKeySlot KeySlot, newOptions ...KDFOption) (KeySlot, error) {
	return defaultCrypt.updatePassword(oldKeySlot, newOptions...)
}

func (k *Crypt) UpdatePassword(oldKeySlot KeySlot, newOptions ...KDFOption) (KeySlot, error) {
	return k.updatePassword(oldKeySlot, newOptions...)
}

func (c *crypt) updatePassword(oldKeySlot KeySlot, newOptions ...KDFOption) (KeySlot, error) {
	if c.masterKey == nil || c.masterKey.data == nil {
		return KeySlot{}, ErrMasterKeyNotSet
	}

	if err := c.verifyPassword(oldKeySlot); err != nil {
		return KeySlot{}, err
	}

	return c.setPassword(newOptions...)
}

func DecryptString(encryptedData string) (string, error) {
	data, err := defaultCrypt.decrypt([]byte(encryptedData))
	return string(data), err
}

func (c *Crypt) DecryptString(encryptedData string) (string, error) {
	data, err := c.decrypt([]byte(encryptedData))
	return string(data), err
}

func Decrypt(encryptedData []byte) ([]byte, error) {
	return defaultCrypt.decrypt(encryptedData)
}

func (c *Crypt) Decrypt(encryptedData []byte) ([]byte, error) {
	return c.decrypt(encryptedData)
}

func (c *crypt) decrypt(encryptedData []byte) ([]byte, error) {
	if c.masterKey == nil || c.masterKey.data == nil {
		return nil, ErrMasterKeyNotSet
	}

	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(encryptedData)))
	n, err := base64.StdEncoding.Decode(decoded, encryptedData)
	if err != nil {
		return nil, fmt.Errorf("error base64-decoding encrypted data: %w", err)
	}
	decoded = decoded[:n]

	decryptedBytes, err := decrypt(decoded, c.masterKey.data)
	if err != nil {
		return nil, fmt.Errorf("error decrypting encrypted data: %w", err)
	}

	return decryptedBytes, nil
}

func EncryptString(data string) (string, error) {
	encryptedData, err := defaultCrypt.encrypt([]byte(data))
	return string(encryptedData), err
}

func (c *Crypt) EncryptString(data string) (string, error) {
	encryptedData, err := c.encrypt([]byte(data))
	return string(encryptedData), err
}

func Encrypt(data []byte) ([]byte, error) {
	return defaultCrypt.encrypt(data)
}

func (c *Crypt) Encrypt(data []byte) ([]byte, error) {
	return c.encrypt(data)
}

func (c *crypt) encrypt(data []byte) ([]byte, error) {
	if c.masterKey == nil || c.masterKey.data == nil {
		return nil, ErrMasterKeyNotSet
	}

	encryptedBytes, err := encrypt(data, c.masterKey.data)
	if err != nil {
		return nil, fmt.Errorf("error encrypting the byte slice of the input string: %w", err)
	}

	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(encryptedBytes)))
	base64.StdEncoding.Encode(encoded, encryptedBytes)

	return encoded, nil
}

func encrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("error creating cipher block: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("error creating GCM block: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("error generating nonce: %w", err)
	}

	return gcm.Seal(nonce, nonce, data, nil), nil
}

func decrypt(encryptedData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("error creating cipher block: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("error creating GCM block: %w", err)
	}

	if len(encryptedData) < gcm.NonceSize() {
		return nil, ErrCipherTextTooShort
	}

	nonce, cipherText := encryptedData[:gcm.NonceSize()], encryptedData[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return nil, fmt.Errorf("error decrypting data: %w", err)
	}

	return plaintext, nil
}
