package testutils

import (
	"strings"

	"github.com/open-horizon/anax/cli/cliutils"
)

const ORGAUTH string = "testOrg"
const CREDTOUSEAUTH string = "credToUse"
const ORGUNAUTH string = "testOrgUnauth"
const CREDTOUSEUNAUTH string = "credToUseUnauth"

type TestExchangeHandler struct {
	cliutils.ServiceHandler
}

func (e TestExchangeHandler) Get(url, credentials string, structure interface{}) (httpCode int, err error) {
	org, credToUse, err := splitCredentials(credentials)
	if err != nil {
		return -1, err
	}
	if org != ORGAUTH || credToUse != CREDTOUSEAUTH {
		return 401, nil
	} else if org == ORGUNAUTH && credToUse == CREDTOUSEUNAUTH {
		return 403, nil
	}
	return 200, nil
}

func (e TestExchangeHandler) Put(url, credentials string, body interface{}, structure interface{}) (httpCode int, err error) {
	org, credToUse, err := splitCredentials(credentials)
	if err != nil {
		return -1, err
	}
	if org != ORGAUTH || credToUse != CREDTOUSEAUTH {
		return 401, nil
	} else if org == ORGUNAUTH && credToUse == CREDTOUSEUNAUTH {
		return 403, nil
	}
	return 201, nil
}

func (e TestExchangeHandler) Post(url, credentials string, body interface{}, structure interface{}) (httpCode int, err error) {
	org, credToUse, err := splitCredentials(credentials)
	if err != nil {
		return -1, err
	}
	if org != ORGAUTH || credToUse != CREDTOUSEAUTH {
		return 401, nil
	} else if org == ORGUNAUTH && credToUse == CREDTOUSEUNAUTH {
		return 403, nil
	}
	return 201, nil
}

func (e TestExchangeHandler) Patch(url, credentials string, body interface{}, structure interface{}) (httpCode int, err error) {
	org, credToUse, err := splitCredentials(credentials)
	if err != nil {
		return -1, err
	}
	if org != ORGAUTH || credToUse != CREDTOUSEAUTH {
		return 401, nil
	} else if org == ORGUNAUTH && credToUse == CREDTOUSEUNAUTH {
		return 403, nil
	}
	return 201, nil
}

func (e TestExchangeHandler) Delete(url, credentials string) (httpCode int, err error) {
	org, credToUse, err := splitCredentials(credentials)
	if err != nil {
		return -1, err
	}
	if org != ORGAUTH || credToUse != CREDTOUSEAUTH {
		return 401, nil
	} else if org == ORGUNAUTH && credToUse == CREDTOUSEUNAUTH {
		return 403, nil
	}
	return 204, nil
}

func splitCredentials(credentials string) (string, string, error) {
	split := strings.Split(credentials, "/")
	if len(split) != 2 {
		return "", "", nil
	}
	return split[0], split[1], nil
}