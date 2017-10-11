package main

import (
//	"crypto/x509"
	"encoding/json"
//	"encoding/pem"
	"io/ioutil"
	"os"
        "strings"
        "unicode"

	"github.com/atlassian/kubetoken"
	"github.com/pkg/errors"
)

type Environment struct {
	Name        string `json:"name"`
	Customer    string `json:"customer"`
	Environment string `json:"env"`
//	caCertPEM   []byte // contents of the CAcert file, as PEM.
	Contexts    []struct {
//		CACert           string            `json:"cacert"`  // path to ca cert
//		PrivKey          string            `json:"privkey"` // path to ca cert private key
//		caCertPEM        []byte            // contents of the CAcert file, as PEM.
                VaultHost        string            `json:"vaulthost"` // vault host to use
                VaultTokenFile   string            `json:"vaulttoken"` // path to vault token
                VaultToken       string            // the actual vault token, read in from secret file
		Clusters         map[string]string `json:"clusters"`
		kubetoken.Signer `json:"-"`
	} `json:"contexts"`
}

type Config struct {
	Environments []Environment `json:"environments"`
}

func loadConfig(p string) (*Config, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var config Config
	dec := json.NewDecoder(f)
	if err := dec.Decode(&config); err != nil {
		return nil, err
	}
	return &config, nil
}

func loadTokens(c *Config) error {
	for i := range c.Environments {
		e := &c.Environments[i]
		for j := range e.Contexts {
			ctx := &e.Contexts[j]
			VaultToken, err := ioutil.ReadFile(ctx.VaultTokenFile)
                        ctx.VaultToken = stripSpaces(string(VaultToken))
			if err != nil {
				return errors.WithMessage(err, ctx.VaultTokenFile)
			}
                }
        }
        return nil
}

func stripSpaces(str string) string {
    return strings.Map(func(r rune) rune {
        if unicode.IsSpace(r) {
            // if the character is a space, drop it
            return -1
        }
        // else keep it in the string
        return r
    }, str)
}
