// main.go - Katzenpost client POP3/SMTP proxy binary.
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

package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"os/user"
	"path"
	"syscall"

	"github.com/katzenpost/core/utils"
	"github.com/katzenpost/mailproxy"
	"github.com/katzenpost/mailproxy/config"
	"github.com/katzenpost/playground"
	"github.com/katzenpost/registration_client"
	rclient "github.com/katzenpost/registration_client/mailproxy"
)

func main() {
	cfgFile := flag.String("f", "katzenpost.toml", "Path to the server config file.")
	genOnly := flag.Bool("g", false, "Generate the keys and exit immediately.")
	register := flag.Bool("r", false, "Register the account")
	accountName := flag.String("account", "", "account name to register")
	providerName := flag.String("provider", playground.ProviderName, "provider to use")
	providerKey := flag.String("providerKey", playground.ProviderKeyPin, "provider to use")

	authority := flag.String("authority", playground.AuthorityAddr, "address of nonvoting pki")
	onionAuthority := flag.String("onionAuthority", playground.OnionAuthorityAddr, ".onion address of nonvoting pki")
	authorityKey := flag.String("authorityKey", playground.AuthorityPublicKey, "authority public key, base64 or hex")

	registrationAddr := flag.String("registrationAddr", playground.RegistrationAddr, "account registration address")
	onionRegistrationAddr := flag.String("onionRegistrationAddr", playground.OnionRegistrationAddr, "account registration address")
	registerWithoutHttps := flag.Bool("registrationWithoutHttps", false, "register using insecure http (for testing environments)")

	registerWithOnion := flag.Bool("onion", false, "register using the Tor onion service")
	socksNet := flag.String("torSocksNet", "tcp", "tor SOCKS network (e.g. tcp or unix)")
	socksAddr := flag.String("torSocksAddr", "127.0.0.1:9150", "tor SOCKS address (e.g. 127.0.0.1:9050")

	dataDir := flag.String("dataDir", "", "mailproxy data directory, defaults to ~/.mailproxy")

	flag.Parse()

	if *register {
		if len(*accountName) == 0 {
			flag.Usage()
			return
		}

		// 1. ensure mailproxy data dir doesn't already exist
		mailproxyDir := ""
		if len(*dataDir) == 0 {
			usr, err := user.Current()
			if err != nil {
				panic("failure to retrieve current user information")
			}
			mailproxyDir = path.Join(usr.HomeDir, ".mailproxy")
		} else {
			mailproxyDir = *dataDir
		}
		if _, err := os.Stat(mailproxyDir); !os.IsNotExist(err) {
			panic(fmt.Sprintf("aborting registration, %s already exists", mailproxyDir))
		}
		if err := utils.MkDataDir(mailproxyDir); err != nil {
			panic(err)
		}

		// 2. generate mailproxy key material and configuration
		linkKey, identityKey, err := rclient.GenerateConfig(*accountName, *providerName, *providerKey, *authority, *onionAuthority, *authorityKey, mailproxyDir, *socksNet, *socksAddr, *registerWithOnion)
		if err != nil {
			panic(err)
		}

		// 3. perform registration with the mixnet Provider
		var options *client.Options = nil
		if *registerWithOnion {
			registrationAddr = onionRegistrationAddr
			options = &client.Options{
				Scheme:       "http",
				UseSocks:     true,
				SocksNetwork: *socksNet,
				SocksAddress: *socksAddr,
			}
		} else if *registerWithoutHttps {
			options = &client.Options{
				Scheme:       "http",
				UseSocks:     false,
				SocksNetwork: "",
				SocksAddress: "",
			}
		}
		c, err := client.New(*registrationAddr, options)
		if err != nil {
			panic(err)
		}
		err = c.RegisterAccountWithIdentityAndLinkKey(*accountName, linkKey, identityKey)
		if err != nil {
			panic(err)
		}

		fmt.Printf("Successfully registered %s@%s\n", *accountName, *providerName)
		fmt.Printf("mailproxy -f %s\n", mailproxyDir+"/mailproxy.toml")
		return
	}

	// Set the umask to something "paranoid".
	syscall.Umask(0077)

	cfg, err := config.LoadFile(*cfgFile, *genOnly)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config file '%v': %v\n", *cfgFile, err)
		os.Exit(-1)
	}

	// Setup the signal handling.
	ch := make(chan os.Signal)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)

	// Start up the proxy.
	proxy, err := mailproxy.New(cfg)
	if err != nil {
		if err == mailproxy.ErrGenerateOnly {
			os.Exit(0)
		}
		fmt.Fprintf(os.Stderr, "Failed to spawn server instance: %v\n", err)
		os.Exit(-1)
	}
	defer proxy.Shutdown()

	// Halt the proxy gracefully on SIGINT/SIGTERM, and scan RecipientDir on SIGHUP.
	go func() {
		for {
			switch <-ch {
			case syscall.SIGHUP:
				proxy.ScanRecipientDir()
			default:
				proxy.Shutdown()
				return
			}
		}
	}()

	// Wait for the proxy to explode or be terminated.
	proxy.Wait()
}
