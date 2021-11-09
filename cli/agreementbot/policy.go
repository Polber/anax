package agreementbot

import (
	"encoding/json"
	"fmt"
	"github.com/open-horizon/anax/cli/cliutils"
	"github.com/open-horizon/anax/i18n"
	"github.com/open-horizon/anax/policy"
	"os"
)

// get the policy names that the agbot hosts
func getPolicyNames(org string) (map[string][]string, int, error) {
	// set env to call agbot url
	if err := os.Setenv("HORIZON_URL", cliutils.GetAgbotUrlBase()); err != nil {
		return nil, 0, cliutils.CLIError{StatusCode: cliutils.CLI_GENERAL_ERROR, Message: i18n.GetMessagePrinter().Sprintf("unable to set env var 'HORIZON_URL', error %v", err)}
	}

	// Get horizon api policy output
	apiOutput := make(map[string][]string, 0)
	httpCode := 200

	var err error
	if org != "" {
		// get the policy names for the given org
		if httpCode, err = cliutils.HorizonGet(fmt.Sprintf("policy/%v", org), []int{200, 400}, &apiOutput, false); err != nil {
			return nil, 0, err
		}
	} else {
		// get all the policy names
		if httpCode, err = cliutils.HorizonGet("policy", []int{200}, &apiOutput, false); err != nil {
			return nil, 0, err
		}
	}

	return apiOutput, httpCode, nil
}

// get the policy with the given name for the given org
func getPolicy(org string, name string) (*policy.Policy, int, error) {
	// set env to call agbot url
	if err := os.Setenv("HORIZON_URL", cliutils.GetAgbotUrlBase()); err != nil {
		return nil, 0, cliutils.CLIError{StatusCode: cliutils.CLI_GENERAL_ERROR, Message: i18n.GetMessagePrinter().Sprintf("unable to set env var 'HORIZON_URL', error %v", err)}
	}

	// Get horizon api policy output
	var apiOutput policy.Policy
	httpCode, err := cliutils.HorizonGet(fmt.Sprintf("policy/%v/%v", org, name), []int{200, 400}, &apiOutput, false)
	if err != nil {
		return nil, 0, err
	}

	return &apiOutput, httpCode, nil
}

func PolicyList(org string, name string) error {
	// get message printer
	msgPrinter := i18n.GetMessagePrinter()

	if name == "" {
		policies, httpCode, err := getPolicyNames(org)
		if err != nil {
			return err
		}
		if httpCode == 200 {
			jsonBytes, err := json.MarshalIndent(policies, "", cliutils.JSON_INDENT)
			if err != nil {
				return cliutils.CLIError{StatusCode: cliutils.JSON_PARSING_ERROR, Message: msgPrinter.Sprintf("failed to marshal 'policy list' output: %v", err)}
			}
			fmt.Printf("%s\n", jsonBytes)
		} else if httpCode == 400 {
			msgPrinter.Printf("Error: The organization '%v' does not exist.", org)
			msgPrinter.Println()
		}
	} else {
		pol, httpCode, err := getPolicy(org, name)
		if err != nil {
			return err
		}
		if httpCode == 200 {
			jsonBytes, err := json.MarshalIndent(pol, "", cliutils.JSON_INDENT)
			if err != nil {
				return cliutils.CLIError{StatusCode: cliutils.JSON_PARSING_ERROR, Message: msgPrinter.Sprintf("failed to marshal 'policy list' output: %v", err)}
			}
			fmt.Printf("%s\n", jsonBytes)
		} else if httpCode == 400 {
			msgPrinter.Printf("Error: Either the organization '%v' does not exist or the policy '%v' is not hosted by this agbot.", org, name)
			msgPrinter.Println()
		}
	}

	return nil
}
