package exchange

import (
	"fmt"
	"github.com/open-horizon/anax/cli/cliutils"
)

func Status(org, userPw string, exchangeHandler cliutils.ServiceHandler) error {
	var output string
	if _, err := exchangeHandler.Get("admin/status", cliutils.OrgAndCreds(org, userPw), &output); err != nil {
		return err
	}
	fmt.Println(output)
	return nil
}
