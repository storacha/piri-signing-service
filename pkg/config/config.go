package config

import (
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/spf13/viper"
	ucantodid "github.com/storacha/go-ucanto/did"
	"github.com/storacha/go-ucanto/principal"
	ed25519 "github.com/storacha/go-ucanto/principal/ed25519/signer"
	"github.com/storacha/go-ucanto/principal/signer"
)

const (
	// Default values - only host and port have defaults
	DefaultHost = "localhost"
	DefaultPort = 7446

	// Environment variable prefix
	EnvPrefix = "SIGNING_SERVICE"

	// Config file name (without extension)
	ConfigFileName = "config"
)

type Config struct {
	Host                   string `mapstructure:"host"`
	Port                   int    `mapstructure:"port"`
	RPCUrl                 string `mapstructure:"rpc_url"`
	ServiceContractAddress string `mapstructure:"service_contract_address"`
	DID                    string `mapstructure:"did"`
	PrivateKey             string `mapstructure:"private_key"`
	PrivateKeyPath         string `mapstructure:"private_key_path"`
	KeystorePath           string `mapstructure:"keystore_path"`
	KeystorePassword       string `mapstructure:"keystore_password"`
}

// InitViper initializes Viper with defaults and binds it to Cobra flags
func Init() error {
	// Set up environment variables
	viper.SetEnvPrefix(EnvPrefix)
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	// Set up config file
	viper.SetConfigName(ConfigFileName)
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".") // Look in current directory

	// Try to read config file (don't fail if not found)
	if err := viper.ReadInConfig(); err != nil {
		// It's OK if the config file doesn't exist
		var configFileNotFoundError viper.ConfigFileNotFoundError
		if !errors.As(err, &configFileNotFoundError) {
			// But return other errors (like parse errors)
			return fmt.Errorf("error reading config file: %w", err)
		}
	}

	return nil
}

// Load reads configuration from viper and validates it
func Load() (*Config, error) {
	var cfg Config

	// Unmarshal config from viper
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshaling config: %w", err)
	}

	// Validate the configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &cfg, nil
}

// Validate checks that required configuration fields are set
func (c *Config) Validate() error {
	// Host and port have defaults, so they should always be set
	if c.Host == "" {
		return fmt.Errorf("host is required")
	}

	if c.Port <= 0 || c.Port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}

	// These fields are required and have no defaults
	if c.RPCUrl == "" {
		return fmt.Errorf("rpc_url is required (set via flag --rpc-url, env SIGNING_SERVICE_RPC_URL, or in signer.yaml)")
	}

	if c.ServiceContractAddress == "" {
		return fmt.Errorf("service_contract_address is required (set via flag --contract-address, env SIGNING_SERVICE_SERVICE_CONTRACT_ADDRESS, or in signer.yaml)")
	}

	if !common.IsHexAddress(c.ServiceContractAddress) {
		return fmt.Errorf("invalid contract address: %s", c.ServiceContractAddress)
	}

	// Must have either private key, private key file or keystore
	if c.PrivateKey == "" && c.PrivateKeyPath == "" && c.KeystorePath == "" {
		return fmt.Errorf("either private_key, private_key_path or keystore_path must be provided (set via flags, env vars, or in signer.yaml)")
	}

	// If using private key, a did web is required
	if c.PrivateKey != "" {
		if c.DID == "" {
			return fmt.Errorf("did is required when using private key")
		}

		if !strings.HasPrefix(c.DID, "did:web:") {
			return fmt.Errorf("did must be a did:web")
		}
	}

	// If using keystore, password is required
	if c.KeystorePath != "" && c.KeystorePassword == "" {
		return fmt.Errorf("keystore_password is required when using keystore")
	}

	return nil
}

// ContractAddr returns the contract address as a common.Address
func (c *Config) ContractAddr() common.Address {
	return common.HexToAddress(c.ServiceContractAddress)
}

// LoadSigner loads a multibase-encoded private key string
// and wraps it in a signer along a DID
func LoadSigner(key string, did string) (principal.Signer, error) {
	k, err := ed25519.Parse(key)
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}

	d, err := ucantodid.Parse(did)
	if err != nil {
		return nil, fmt.Errorf("parsing DID: %w", err)
	}

	s, err := signer.Wrap(k, d)
	if err != nil {
		return nil, fmt.Errorf("wrapping server DID: %w", err)
	}

	return s, nil
}

// LoadPrivateKeyFromFile loads a private key from a file
// The file can contain either hex-encoded or raw bytes
func LoadPrivateKeyFromFile(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading private key file: %w", err)
	}

	// Trim whitespace
	keyData := strings.TrimSpace(string(data))

	// Try hex decoding first
	keyData = strings.TrimPrefix(keyData, "0x")

	keyBytes, err := hex.DecodeString(keyData)
	if err != nil {
		// If hex decoding fails, try using the raw bytes
		keyBytes = data
	}

	privateKey, err := crypto.ToECDSA(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}

	return privateKey, nil
}

// LoadPrivateKeyFromKeystore loads a private key from an encrypted keystore file
func LoadPrivateKeyFromKeystore(keystorePath, password string) (*ecdsa.PrivateKey, error) {
	keystoreJSON, err := os.ReadFile(keystorePath)
	if err != nil {
		return nil, fmt.Errorf("reading keystore file: %w", err)
	}

	key, err := keystore.DecryptKey(keystoreJSON, password)
	if err != nil {
		return nil, fmt.Errorf("decrypting keystore: %w", err)
	}

	return key.PrivateKey, nil
}
