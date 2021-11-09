package exchange

import (
	"fmt"
	"github.com/open-horizon/anax/cli/cliutils"
	"strings"
)

func Version(org string, userPw string, exchangeHandler cliutils.ServiceHandler) error {
	output, err := LoadExchangeVersion(true, org, exchangeHandler, userPw)
	if err != nil {
		return err
	}
	fmt.Println(output)
	return nil
}

// Loads exchange version based on optional org and optional set of prioritized credentials (first non-empty credentials will be used)
// If loadWithoutCredentials is false and credentials are missing - the version loading will not be executed (empty string will be returned)
func LoadExchangeVersion(loadWithoutCredentials bool, org string, exchangeHandler cliutils.ServiceHandler, userPws ...string) (string, error) {
	var credToUse string
	for _, cred := range userPws {
		if cred != "" {
			credToUse = cred
			break
		}
	}
	var output []byte
	// Note: the base exchange does not need creds for this call (although is tolerant of it), but some front-ends to the exchange might
	if credToUse != "" {
		cliutils.SetWhetherUsingApiKey(credToUse)
		if _, err := exchangeHandler.Get("admin/version", cliutils.OrgAndCreds(org, credToUse), &output); err != nil {
			return "", err
		}
	} else if loadWithoutCredentials {
		if _, err := exchangeHandler.Get("admin/version", credToUse, &output); err != nil {
			return "", err
		}
	}
	return strings.TrimSpace(string(output)), nil
}
