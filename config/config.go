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
	vClient "github.com/katzenpost/authority/voting/client"
	vServerConfig "github.com/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/core/log"
	"github.com/katzenpost/core/pki"
	"github.com/katzenpost/core/utils"
	"github.com/katzenpost/mailproxy/event"
	"github.com/katzenpost/mailproxy/internal/authority"
	"github.com/katzenpost/mailproxy/internal/proxy"
	"golang.org/x/net/idna"
	"golang.org/x/text/secure/precis"
)

const (
	defaultPOP3Addr            = "127.0.0.1:2524"
	defaultSMTPAddr            = "127.0.0.1:2525"
	defaultLogLevel            = "NOTICE"
	defaultManagementSocket    = "management_sock"
	defaultBounceQueueLifetime = 432000 // 5 days.
	defaultUrgentQueueLifetime = 3600   // 1 hour.
	defaultPollingInterval     = 30     // 30 seconds.
	defaultRetransmitSlack     = 300    // 5 minutes.
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

	// RecipientDir is the absolute path to the mail proxy's recipient files.
	RecipientDir string

	// NoLaunchListeners disables the POP3 and SMTP interfaces, which is
	// useful if you are using mailproxy as a library rather than a
	// stand-alone process.
	NoLaunchListeners bool

	// EventSink is the API event sink.
	EventSink chan event.Event `toml:"-"`
}

func (pCfg *Proxy) applyDefaults() {
	if pCfg.POP3Address == "" {
		pCfg.POP3Address = defaultPOP3Addr
	}
	if pCfg.SMTPAddress == "" {
		pCfg.SMTPAddress = defaultSMTPAddr
	}
	if pCfg.RecipientDir == "" {
		pCfg.RecipientDir = filepath.Join(pCfg.DataDir, "recipients")
	}
}

func (pCfg *Proxy) validate() error {
	if !pCfg.NoLaunchListeners {
		if err := utils.EnsureAddrIPPort(pCfg.POP3Address); err != nil {
			return fmt.Errorf("config: Proxy: POP3Address '%v' is invalid: %v", pCfg.POP3Address, err)
		}
		if err := utils.EnsureAddrIPPort(pCfg.SMTPAddress); err != nil {
			return fmt.Errorf("config: Proxy: SMTPAddress '%v' is invalid: %v", pCfg.SMTPAddress, err)
		}
	}
	if !filepath.IsAbs(pCfg.DataDir) {
		return fmt.Errorf("config: Proxy: DataDir '%v' is not an absolute path", pCfg.DataDir)
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
	// ReceiveTimeout is the time in seconds after which the inbound
	// message processor will give up on a partially received message
	// measured from when the last non-duplicate fragment was received.
	// If set to 0 (the default), the timeout is infinite.
	ReceiveTimeout int

	// BounceQueueLifetime is the minimum time in seconds till the mail
	// proxy will give up on sending a particular e-mail.
	BounceQueueLifetime int

	// UrgentQueueLifetime is the minimum time in seconds till the mail
	// proxy will give up on sending urgent (Kaetzchen) requests.
	UrgentQueueLifetime int

	// PollingInterval is the interval in seconds that will be used to
	// poll the receive queue.  By default this is 30 seconds.  Reducing
	// the value too far WILL result in uneccesary Provider load, and
	// increasing the value too far WILL adversely affect large message
	// transmit performance.
	PollingInterval int

	// RetransmitSlack is the extra time in seconds added to account for
	// various delays such as latency and the fetch scheduler before
	// a block will be retransmitted.  Reducing this WILL result in
	// worse performance, increased spurrious retransmissions, and
	// unneccecary load on the network.
	RetransmitSlack int

	// CaseSensitiveUserIdentifiers disables the forced lower casing of
	// the Account `User` field.
	CaseSensitiveUserIdentifiers bool

	// SendDecoyTraffic enables sending decoy traffic.  This is still
	// experimental and untuned and thus is disabled by default.
	//
	// WARNING: This option will go away once a concrete client decoy
	// traffic is more concrete.
	SendDecoyTraffic bool

	// GenerateOnly halts and cleans up the mail proxy right after long term
	// key generation.
	GenerateOnly bool
}

func (dCfg *Debug) applyDefaults() {
	if dCfg.ReceiveTimeout < 0 {
		dCfg.ReceiveTimeout = 0
	}
	if dCfg.BounceQueueLifetime <= 0 {
		dCfg.BounceQueueLifetime = defaultBounceQueueLifetime
	}
	if dCfg.UrgentQueueLifetime <= 0 {
		dCfg.UrgentQueueLifetime = defaultUrgentQueueLifetime
	}
	if dCfg.PollingInterval <= 0 {
		dCfg.PollingInterval = defaultPollingInterval
	}
	if dCfg.RetransmitSlack <= 0 {
		dCfg.RetransmitSlack = defaultRetransmitSlack
	}
}

// VotingPeer is the mail proxy authority peer configuration.
type VotingPeer struct {
	// Address is the IP address/port combination of the authority.
	Addresses []string

	// IdentityPublicKey is the authority's signing public key.
	IdentityPublicKey *eddsa.PublicKey

	// LinkPublicKey is the authority's link layer public key.
	LinkPublicKey *eddsa.PublicKey
}

func (peer *VotingPeer) validate() error {
	if len(peer.Addresses) == 0 {
		return errors.New("Addresses must be specified.")
	}
	for _, addr := range peer.Addresses {
		if err := utils.EnsureAddrIPPort(addr); err != nil {
			return fmt.Errorf("Address '%v' is invalid: %v", addr, err)
		}
	}
	if peer.IdentityPublicKey == nil {
		return fmt.Errorf("Identity PublicKey is missing")
	}
	if peer.LinkPublicKey == nil {
		return fmt.Errorf("Link PublicKey is missing")
	}
	return nil
}

// VotingAuthority is a voting authority configuration.
type VotingAuthority struct {
	Peers []*vServerConfig.AuthorityPeer
}

// New constructs a pki.Client with the specified non-voting authority config.
func (vACfg *VotingAuthority) New(l *log.Backend, pCfg *proxy.Config) (pki.Client, error) {
	cfg := &vClient.Config{
		LogBackend:    l,
		Authorities:   vACfg.Peers,
		DialContextFn: pCfg.ToDialContext("voting"),
	}
	return vClient.New(cfg)
}

func (vACfg *VotingAuthority) validate() error {
	if vACfg.Peers == nil || len(vACfg.Peers) == 0 {
		return errors.New("VotingAuthority failure, must specify at least one peer.")
	}
	for _, peer := range vACfg.Peers {
		err := peer.Validate()
		if err != nil {
			return err
		}
	}
	return nil
}

// NonvotingAuthority is a non-voting authority configuration.
type NonvotingAuthority struct {
	// Address is the IP address/port combination of the authority.
	Address string

	// PublicKey is the authority's public key.
	PublicKey *eddsa.PublicKey
}

// New constructs a pki.Client with the specified non-voting authority config.
func (nvACfg *NonvotingAuthority) New(l *log.Backend, pCfg *proxy.Config) (pki.Client, error) {
	cfg := &nvClient.Config{
		LogBackend:    l,
		Address:       nvACfg.Address,
		PublicKey:     nvACfg.PublicKey,
		DialContextFn: pCfg.ToDialContext("nonvoting:" + nvACfg.PublicKey.String()),
	}
	return nvClient.New(cfg)
}

func (nvACfg *NonvotingAuthority) validate() error {
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

	// VotingAuthority is the authority configuration used by this Account.
	VotingAuthority string

	// NonvotingAuthority is the authority configuration used by this Account.
	NonvotingAuthority string

	// LinkKey is the Provider authentication key used by this Account.
	LinkKey *ecdh.PrivateKey `toml:"-"`

	// IdentityKey is the identity key used by this Account.
	IdentityKey *ecdh.PrivateKey `toml:"-"`

	// StorageKey is the optional per-account database encryption key.
	StorageKey *ecdh.PrivateKey `toml:"-"`

	// InsecureKeyDiscovery enables automatic fetching of recipient keys.
	// This option is disabled by default as mailproxy provides no UX for
	// verifying keys.
	InsecureKeyDiscovery bool
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
	_, aok := cfg.nonvotingAuthorities[accCfg.NonvotingAuthority]
	_, bok := cfg.votingAuthorities[accCfg.VotingAuthority]
	if !aok && !bok {
		return fmt.Errorf("non-existent Voting/Nonvoting Authority")
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

// UpstreamProxy is the mailproxy outgoing connection proxy configuration.
type UpstreamProxy struct {
	// PreferedTransports is a list of the transports will be used to make
	// outgoing network connections, with the most prefered first.
	PreferedTransports []pki.Transport

	// Type is the proxy type (Eg: "none"," socks5").
	Type string

	// Network is the proxy address' network (`unix`, `tcp`).
	Network string

	// Address is the proxy's address.
	Address string

	// User is the optional proxy username.
	User string

	// Password is the optional proxy password.
	Password string
}

func (uCfg *UpstreamProxy) toProxyConfig() (*proxy.Config, error) {
	// This is kind of dumb, but this is the cleanest way I can think of
	// doing this.
	cfg := &proxy.Config{
		PreferedTransports: uCfg.PreferedTransports,
		Type:               uCfg.Type,
		Network:            uCfg.Network,
		Address:            uCfg.Address,
		User:               uCfg.User,
		Password:           uCfg.Password,
	}
	if err := cfg.FixupAndValidate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Config is the top level mail proxy configuration.
type Config struct {
	Proxy         *Proxy
	Logging       *Logging
	Management    *Management
	UpstreamProxy *UpstreamProxy
	Debug         *Debug

	NonvotingAuthority map[string]*NonvotingAuthority
	VotingAuthority    map[string]*VotingAuthority
	Account            []*Account
	Recipients         map[string]*ecdh.PublicKey `toml:"-"`

	nonvotingAuthorities map[string]authority.Factory
	votingAuthorities    map[string]authority.Factory
	accounts             map[string]*Account
	upstreamProxy        *proxy.Config

	// StrRecipients exists entirely to work around a bug in the toml library,
	// and should not be used by anything external to this package.
	//
	// See: https://github.com/BurntSushi/toml/issues/170
	StrRecipients map[string]string `toml:"Recipients"`
}

// VotingAuthorityMap returns the identifier->authority.Factory mapping specified in
// the Config.
func (cfg *Config) VotingAuthorityMap() map[string]authority.Factory {
	return cfg.votingAuthorities
}

// NonvotingAuthorityMap returns the identifier->authority.Factory mapping specified in
// the Config.
func (cfg *Config) NonvotingAuthorityMap() map[string]authority.Factory {
	return cfg.nonvotingAuthorities
}

// AccountMap returns the account identifier->Account mapping specified in the
// Config.
func (cfg *Config) AccountMap() map[string]*Account {
	return cfg.accounts
}

// UpstreamProxyConfig returns the configured upstream proxy, suitable for
// internal use.  Most people should not use this.
func (cfg *Config) UpstreamProxyConfig() *proxy.Config {
	return cfg.upstreamProxy
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
	if cfg.UpstreamProxy == nil {
		cfg.UpstreamProxy = &UpstreamProxy{}
	}
	if cfg.Debug == nil {
		cfg.Debug = &Debug{}
	}
	cfg.Debug.applyDefaults()
	if cfg.Recipients == nil {
		cfg.Recipients = make(map[string]*ecdh.PublicKey)
	}
	if cfg.StrRecipients == nil {
		cfg.StrRecipients = make(map[string]string)
	}
	cfg.nonvotingAuthorities = make(map[string]authority.Factory)
	cfg.votingAuthorities = make(map[string]authority.Factory)
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
	uCfg, err := cfg.UpstreamProxy.toProxyConfig()
	if err != nil {
		return err
	}
	cfg.upstreamProxy = uCfg
	for k, v := range cfg.NonvotingAuthority {
		if err := v.validate(); err != nil {
			return fmt.Errorf("config: NonvotingAuthority '%v' is invalid: %v", k, err)
		}
		if _, ok := cfg.votingAuthorities[k]; ok {
			return fmt.Errorf("config: Authority '%v' is defined multiple times", k)
		}
		cfg.nonvotingAuthorities[k] = v
	}
	for k, v := range cfg.VotingAuthority {
		if err := v.validate(); err != nil {
			return fmt.Errorf("config: VotingAuthority '%v' is invalid: %v", k, err)
		}
		if _, ok := cfg.votingAuthorities[k]; ok {
			return fmt.Errorf("config: Authority '%v' is defined multiple times", k)
		}
		cfg.votingAuthorities[k] = v
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
	for k, v := range cfg.StrRecipients {
		if _, ok := cfg.Recipients[k]; ok {
			return fmt.Errorf("config: Recipient '%v' defined multiple times", k)
		}
		pk := new(ecdh.PublicKey)
		if err := pk.FromString(v); err != nil {
			return fmt.Errorf("config: Recipient '%v' is invalid: %v", k, err)
		}
		cfg.Recipients[k] = pk
	}

	return nil
}

// Load parses and validates the provided buffer b as a config file body and
// returns the Config.
func Load(b []byte, forceGenOnly bool) (*Config, error) {
	cfg := new(Config)
	md, err := toml.Decode(string(b), cfg)
	if err != nil {
		return nil, err
	}
	if undecoded := md.Undecoded(); len(undecoded) != 0 {
		return nil, fmt.Errorf("config: Undecoded keys in config file: %v", undecoded)
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
