package sync_service

import (
	"fmt"
	"github.com/open-horizon/anax/cli/cliutils"
	"github.com/open-horizon/anax/i18n"
	"github.com/open-horizon/edge-sync-service/common"
	"path"
)

type MMSHealth struct {
	General  common.HealthStatusInfo   `json:"general"`
	DBHealth common.DBHealthStatusInfo `json:"dbHealth"`
}

func Status(org string, userPw string, mmsHandler cliutils.ServiceHandler) error {
	// get message printer
	msgPrinter := i18n.GetMessagePrinter()

	if userPw == "" {
		return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, msgPrinter.Sprintf("must specify exchange credentials to access the model management service"))
	}

	// Set the API key env var if that's what we're using.
	cliutils.SetWhetherUsingApiKey(userPw)

	// Display the minimal health status.
	var healthData MMSHealth

	// Construct the URL path from the input pieces. They are required inputs so we know they are at least non-null.
	urlPath := path.Join("api/v1/health")

	// Call the MMS service over HTTP
	if httpCode, err := mmsHandler.Get(urlPath, cliutils.OrgAndCreds(org, userPw), &healthData); err != nil {
		return err
	} else if httpCode != 200 {
		return cliutils.CLIError{StatusCode: cliutils.HTTP_ERROR, msgPrinter.Sprintf("health status API returned HTTP code %v", httpCode))
	}
	output, err := cliutils.MarshalIndent(healthData, "mms health")
	if err != nil {
		return err
	}
	fmt.Println(output)

	return nil
}
