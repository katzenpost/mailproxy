// config.go - Katzenpost client mail proxy configuration.
// Copyright (C) 2017  Yawning Angel.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// Package config implements the configuration for the Katzenpost client mail
// proxy.
package config

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/mail"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	nvClient "github.com/katzenpost/authority/nonvoting/client"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/core/log"
	"github.com/katzenpost/core/pki"
	"github.com/katzenpost/core/utils"
	"github.com/katzenpost/mailproxy/internal/authority"
	"golang.org/x/net/idna"
	"golang.org/x/text/secure/precis"
)

const (
	defaultPOP3Addr            = "127.0.0.1:2524"
	defaultSMTPAddr            = "127.0.0.1:2525"
	defaultLogLevel            = "NOTICE"
	defaultManagementSocket    = "management_sock"
	defaultBounceQueueLifetime = 432000 // 5 days.
	defaultRetransmitSlack     = 300    // 5 minutes.
	defaultTransmitTau         = 5000   // 5 seconds. (TODO: Tune this.)
)

var defaultLogging = Logging{
	Disable: false,
	File:    "",
	Level:   defaultLogLevel,
}

// Proxy is the mail proxy configuration.
type Proxy struct {
	// POP3Address is the IP address/port combination that the mail proxy will
	// bind to for POP3 access.  If omitted `127.0.0.1:2524` will be used.
	POP3Address string

	// SMTPAddress is the IP address/port combination that the mail proxy will
	// bind to for SMTP access.  If omitted `127.0.0.1:2525` will be used.
	SMTPAddress string

	// DataDir is the absolute path to the mail proxy's state files.
	DataDir string
}

func (pCfg *Proxy) applyDefaults() {
	if pCfg.POP3Address == "" {
		pCfg.POP3Address = defaultPOP3Addr
	}
	if pCfg.SMTPAddress == "" {
		pCfg.SMTPAddress = defaultSMTPAddr
	}
}

func (pCfg *Proxy) validate() error {
	if err := utils.EnsureAddrIPPort(pCfg.POP3Address); err != nil {
		return fmt.Errorf("config: Proxy: POP3Address '%v' is invalid: %v", pCfg.POP3Address, err)
	}
	if err := utils.EnsureAddrIPPort(pCfg.SMTPAddress); err != nil {
		return fmt.Errorf("config: Proxy: SMTPAddress '%v' is invalid: %v", pCfg.SMTPAddress, err)
	}
	if !filepath.IsAbs(pCfg.DataDir) {
		return fmt.Errorf("config: ProxyL DataDir '%v' is not an absolute path", pCfg.DataDir)
	}
	return nil
}

// Logging is the mail proxy logging configuration.
type Logging struct {
	// Disable disables logging entirely.
	Disable bool

	// File specifies the log file, if omitted stdout will be used.
	File string

	// Level specifies the log level.
	Level string
}

func (lCfg *Logging) validate() error {
	lvl := strings.ToUpper(lCfg.Level)
	switch lvl {
	case "ERROR", "WARNING", "NOTICE", "INFO", "DEBUG":
	case "":
		lCfg.Level = defaultLogLevel
	default:
		return fmt.Errorf("config: Logging: Level '%v' is invalid", lCfg.Level)
	}
	lCfg.Level = lvl // Force uppercase.
	return nil
}

// Debug is the mail proxy debug configuration.
type Debug struct {
	// BounceQueueLifetime is the minimum time in seconds till the mail
	// proxy will give up on sending a particular e-mail.
	BounceQueueLifetime int

	// RetransmitSlack is the extra time in seconds added to account for
	// various delays such as latency and the fetch scheduler before
	// a block will be retransmitted.  Reducing this WILL result in
	// worse performance, increased spurrious retransmissions, and
	// unneccecary load on the network.
	RetransmitSlack int

	// TransmitTau is the magic send scheduling tuning parameter.
	TransmitTau int

	// CaseSensitiveUserIdentifiers disables the forced lower casing of
	// the Account `User` field.
	CaseSensitiveUserIdentifiers bool

	// GenerateOnly halts and cleans up the mail proxy right after long term
	// key generation.
	GenerateOnly bool
}

func (dCfg *Debug) applyDefaults() {
	if dCfg.BounceQueueLifetime <= 0 {
		dCfg.BounceQueueLifetime = defaultBounceQueueLifetime
	}
	if dCfg.RetransmitSlack <= 0 {
		dCfg.RetransmitSlack = defaultRetransmitSlack
	}
	if dCfg.TransmitTau <= 0 {
		dCfg.TransmitTau = defaultTransmitTau
	}
}

// NonvotingAuthority is a non-voting authority configuration.
type NonvotingAuthority struct {
	// Address is the IP address/port combination of the authority.
	Address string

	// PublicKey is the authority's public key.
	PublicKey *eddsa.PublicKey
}

// New constructs a pki.Client with the specified non-voting authority config.
func (nvACfg *NonvotingAuthority) New(l *log.Backend) (pki.Client, error) {
	cfg := &nvClient.Config{
		LogBackend: l,
		Address:    nvACfg.Address,
		PublicKey:  nvACfg.PublicKey,
	}
	return nvClient.New(cfg)
}

func (nvACfg *NonvotingAuthority) validate() error {
	if err := utils.EnsureAddrIPPort(nvACfg.Address); err != nil {
		return fmt.Errorf("Address '%v' is invalid: %v", nvACfg.Address, err)
	}
	if nvACfg.PublicKey == nil {
		return fmt.Errorf("PublicKey is missing")
	}
	return nil
}

// Account is a provider account configuration.
type Account struct {
	// User is the account user name.
	User string

	// Provider is the provider identifier used by this account.
	Provider string

	// ProviderKeyPin is the optional pinned provider signing key.
	ProviderKeyPin *eddsa.PublicKey

	// Authority is the authority configuration used by this Account.
	Authority string

	forcedLinkKey     *ecdh.PrivateKey
	forcedIdentityKey *ecdh.PrivateKey
	storageKey        *ecdh.PrivateKey
}

// ForcedLinkKey returns the Account's overridden link key if any.
func (accCfg *Account) ForcedLinkKey() *ecdh.PrivateKey {
	return accCfg.forcedLinkKey
}

// SetForcedLinkKey sets the Account's link key to an existing private key.
func (accCfg *Account) SetForcedLinkKey(k *ecdh.PrivateKey) {
	accCfg.forcedLinkKey = k
}

// ForcedIdentityKey returns the Account's overridden identity key if any.
func (accCfg *Account) ForcedIdentityKey() *ecdh.PrivateKey {
	return accCfg.forcedIdentityKey
}

// SetForcedIdentityKey sets the Account's identity key to an existing private
// key.
func (accCfg *Account) SetForcedIdentityKey(k *ecdh.PrivateKey) {
	accCfg.forcedIdentityKey = k
}

// StorageKey returns the optional per-Account database's encryption key if
// any.
func (accCfg *Account) StorageKey() *ecdh.PrivateKey {
	return accCfg.storageKey
}

// SetStorageKey sets the optional per-Account database's encryption key to
// an existing private key.
func (accCfg *Account) SetStorageKey(k *ecdh.PrivateKey) {
	accCfg.storageKey = k
}

func (accCfg *Account) fixup(cfg *Config) error {
	var err error
	if !cfg.Debug.CaseSensitiveUserIdentifiers {
		accCfg.User, err = precis.UsernameCaseMapped.String(accCfg.User)
	} else {
		accCfg.User, err = precis.UsernameCasePreserved.String(accCfg.User)
	}
	if err != nil {
		return err
	}

	accCfg.Provider, err = idna.Lookup.ToASCII(accCfg.Provider)
	return err
}

func (accCfg *Account) toEmailAddr() (string, error) {
	addr := fmt.Sprintf("%s@%s", accCfg.User, accCfg.Provider)
	if _, err := mail.ParseAddress(addr); err != nil {
		return "", fmt.Errorf("User/Provider does not form a valid e-mail address: %v", err)
	}
	return addr, nil
}

func (accCfg *Account) validate(cfg *Config) error {
	if accCfg.User == "" {
		return fmt.Errorf("User is missing")
	}
	if accCfg.Provider == "" {
		return fmt.Errorf("Provider is missing")
	}
	if _, ok := cfg.authorities[accCfg.Authority]; !ok {
		return fmt.Errorf("non-existent Authority '%v'", accCfg.Authority)
	}
	return nil
}

// Management is the mailproxy management interface configuration.
type Management struct {
	// Enable enables the management interface.
	Enable bool

	// Path specifies the path to the management interface socket.  If left
	// empty it will use `management_sock` under the DataDir.
	Path string
}

func (mCfg *Management) applyDefaults(pCfg *Proxy) {
	if mCfg.Path == "" {
		mCfg.Path = filepath.Join(pCfg.DataDir, defaultManagementSocket)
	}
}

func (mCfg *Management) validate() error {
	if !mCfg.Enable {
		return nil
	}
	if !filepath.IsAbs(mCfg.Path) {
		return fmt.Errorf("config: Management: Path '%v' is not an absolute path", mCfg.Path)
	}
	return nil
}

// Config is the top level mail proxy configuration.
type Config struct {
	Proxy      *Proxy
	Logging    *Logging
	Management *Management
	Debug      *Debug

	NonvotingAuthority map[string]*NonvotingAuthority
	Account            []*Account
	Recipients         map[string]*ecdh.PublicKey

	authorities map[string]authority.Factory
	accounts    map[string]*Account
}

// AuthorityMap returns the identifier->authority.Factory mapping specified in
// the Config.
func (cfg *Config) AuthorityMap() map[string]authority.Factory {
	return cfg.authorities
}

// AccountMap returns the account identifier->Account mapping specified in the
// Config.
func (cfg *Config) AccountMap() map[string]*Account {
	return cfg.accounts
}

// FixupAndValidate applies defaults to config entries and validates the
// supplied configuration.  Most people should call one of the Load variants
// instead.
func (cfg *Config) FixupAndValidate() error {
	// Handle missing sections if possible.
	if cfg.Proxy == nil {
		return errors.New("config: No Proxy block was present")
	}
	cfg.Proxy.applyDefaults()
	if cfg.Logging == nil {
		cfg.Logging = &defaultLogging
	}
	if cfg.Management == nil {
		cfg.Management = &Management{}
	}
	cfg.Management.applyDefaults(cfg.Proxy)
	if cfg.Debug == nil {
		cfg.Debug = &Debug{}
	}
	cfg.Debug.applyDefaults()
	if cfg.Recipients == nil {
		cfg.Recipients = make(map[string]*ecdh.PublicKey)
	}
	cfg.authorities = make(map[string]authority.Factory)
	cfg.accounts = make(map[string]*Account)

	// Validate/fixup the various sections.
	if err := cfg.Proxy.validate(); err != nil {
		return err
	}
	if err := cfg.Logging.validate(); err != nil {
		return err
	}
	if err := cfg.Management.validate(); err != nil {
		return err
	}
	for k, v := range cfg.NonvotingAuthority {
		if err := v.validate(); err != nil {
			return fmt.Errorf("config: NonvotingAuthority '%v' is invalid: %v", k, err)
		}
		if _, ok := cfg.authorities[k]; ok {
			return fmt.Errorf("config: Authority '%v' is defined multiple times", k)
		}
		cfg.authorities[k] = v
	}
	for idx, v := range cfg.Account {
		if err := v.fixup(cfg); err != nil {
			return fmt.Errorf("config: Account #%d is invalid (User): %v", idx, err)
		}
		addr, err := v.toEmailAddr()
		if err != nil {
			return fmt.Errorf("config: Account #%d is invalid (Identifier): %v", idx, err)
		}
		if err := v.validate(cfg); err != nil {
			return fmt.Errorf("config: Account '%v' is invalid: %v", addr, err)
		}
		if _, ok := cfg.accounts[addr]; ok {
			return fmt.Errorf("config: Account '%v' is defined multiple times", addr)
		}
		cfg.accounts[addr] = v
	}

	return nil
}

// Load parses and validates the provided buffer b as a config file body and
// returns the Config.
func Load(b []byte, forceGenOnly bool) (*Config, error) {
	cfg := new(Config)
	if err := toml.Unmarshal(b, cfg); err != nil {
		return nil, err
	}
	if err := cfg.FixupAndValidate(); err != nil {
		return nil, err
	}

	if forceGenOnly {
		cfg.Debug.GenerateOnly = true
	}

	return cfg, nil
}

// LoadFile loads, parses, and validates the provided file and returns the
// Config.
func LoadFile(f string, forceGenOnly bool) (*Config, error) {
	b, err := ioutil.ReadFile(f)
	if err != nil {
		return nil, err
	}
	return Load(b, forceGenOnly)
}
