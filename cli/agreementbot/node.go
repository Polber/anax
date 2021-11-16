package agreementbot

import (
	"encoding/json"
	"fmt"
	"github.com/open-horizon/anax/agreementbot"
	"github.com/open-horizon/anax/apicommon"
	"github.com/open-horizon/anax/cli/cliutils"
	"github.com/open-horizon/anax/i18n"
	"os"
)

// This is a combo of anax's HorizonDevice and Info (status) structs
type AgbotAndStatus struct {
	// from agreementbot.HorizonAgbot
	Id  string `json:"agbot_id"`
	Org string `json:"organization"`
	// from apicommon.Info
	Configuration *apicommon.Configuration `json:"configuration"`
	Connectivity  map[string]bool          `json:"connectivity,omitempty"`
}

// CopyNodeInto copies the node info into our output struct
func (n *AgbotAndStatus) CopyNodeInto(horDevice *agreementbot.HorizonAgbot) {
	//todo: I don't like having to repeat all of these fields, hard to maintain. Maybe use reflection?
	n.Id = horDevice.Id
	n.Org = horDevice.Org
}

// CopyStatusInto copies the status info into our output struct
func (n *AgbotAndStatus) CopyStatusInto(status *apicommon.Info) {
	//todo: I don't like having to repeat all of these fields, hard to maintain. Maybe use reflection?
	n.Configuration = status.Configuration
}

func List() error {
	// set env to call agbot url
	if err := os.Setenv("HORIZON_URL", cliutils.GetAgbotUrlBase()); err != nil {
		return cliutils.CLIError{StatusCode: cliutils.CLI_GENERAL_ERROR, Message: i18n.GetMessagePrinter().Sprintf("unable to set env var 'HORIZON_URL', error %v", err)}
	}

	// Get the agbot info
	horDevice := agreementbot.HorizonAgbot{}
	cliutils.HorizonGet("node", []int{200}, &horDevice, false)
	nodeInfo := AgbotAndStatus{} // the structure we will output
	nodeInfo.CopyNodeInto(&horDevice)

	// Get the horizon status info
	status := apicommon.Info{}
	cliutils.HorizonGet("status", []int{200}, &status, false)
	nodeInfo.CopyStatusInto(&status)

	// Output the combined info
	jsonBytes, err := json.MarshalIndent(nodeInfo, "", cliutils.JSON_INDENT)
	if err != nil {
		return cliutils.CLIError{StatusCode: cliutils.JSON_PARSING_ERROR, Message: i18n.GetMessagePrinter().Sprintf("failed to marshal 'hzn node list' output: %v", err)}
	}
	fmt.Printf("%s\n", jsonBytes) //todo: is there a way to output with json syntax highlighting like jq does?

	return nil
}
