package exchange

import (
	"encoding/json"
	"fmt"
	"github.com/open-horizon/anax/cli/cliutils"
	"github.com/open-horizon/anax/exchange"
	"github.com/open-horizon/anax/i18n"
	"os"
)

// We only care about handling the agbot names, so the rest is left as interface{} and will be passed from the exchange to the display
type ExchangeAgbots struct {
	LastIndex int                    `json:"lastIndex"`
	Agbots    map[string]interface{} `json:"agbots"`
}

func AgbotList(org string, userPw string, agbot string, namesOnly bool, exchangeHandler cliutils.ServiceHandler) error {
	cliutils.SetWhetherUsingApiKey(userPw)
	var agbotOrg string
	var err error
	if agbotOrg, agbot, err = cliutils.TrimOrg(org, agbot); err != nil {
		return err
	}
	if agbot == "*" {
		agbot = ""
	}
	if namesOnly && agbot == "" {
		// Only display the names
		var resp ExchangeAgbots
		exchangeHandler.Get("orgs/"+agbotOrg+"/agbots"+cliutils.AddSlash(agbot), cliutils.OrgAndCreds(org, userPw), &resp)
		agbots := []string{}
		for a := range resp.Agbots {
			agbots = append(agbots, a)
		}
		jsonBytes, err := json.MarshalIndent(agbots, "", cliutils.JSON_INDENT)
		if err != nil {
			return cliutils.CLIError{StatusCode: cliutils.JSON_PARSING_ERROR, i18n.GetMessagePrinter().Sprintf("failed to marshal 'exchange agbot list' output: %v", err))
		}
		fmt.Printf("%s\n", jsonBytes)
	} else {
		// Display the full resources
		var agbots ExchangeAgbots
		if httpCode, err := exchangeHandler.Get("orgs/"+agbotOrg+"/agbots"+cliutils.AddSlash(agbot), cliutils.OrgAndCreds(org, userPw), &agbots); err != nil {
			return err
		} else if httpCode == 404 && agbot != "" {
			return cliutils.CLIError{StatusCode: cliutils.NOT_FOUND, i18n.GetMessagePrinter().Sprintf("agbot '%s' not found in org %s", agbot, agbotOrg))
		}
		output, err := cliutils.MarshalIndent(agbots.Agbots, "exchange agbots list")
		if err != nil {
			return err
		}
		fmt.Println(output)
	}

	return nil
}

func formServicedObjectId(objOrg, obj, nodeOrg string) string {
	return objOrg + "_" + obj + "_" + nodeOrg
}

type ExchangeAgbotPatterns struct {
	Patterns map[string]interface{} `json:"patterns"`
}

func AgbotListPatterns(org, userPw, agbot, patternOrg, pattern, nodeOrg string, exchangeHandler cliutils.ServiceHandler) error {
	cliutils.SetWhetherUsingApiKey(userPw)
	var agbotOrg string
	var err error
	if agbotOrg, agbot, err = cliutils.TrimOrg(org, agbot); err != nil {
		return err
	}
	var patternId string
	if patternOrg != "" || pattern != "" {
		if patternOrg == "" || pattern == "" {
			return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, i18n.GetMessagePrinter().Sprintf("both patternorg and pattern must be specified (or neither)"))
		}
		if nodeOrg == "" {
			nodeOrg = patternOrg
		}
		patternId = formServicedObjectId(patternOrg, pattern, nodeOrg)
	}
	// Display the full resources
	var patterns ExchangeAgbotPatterns
	if httpCode, err := exchangeHandler.Get("orgs/"+agbotOrg+"/agbots/"+agbot+"/patterns"+cliutils.AddSlash(patternId), cliutils.OrgAndCreds(org, userPw), &patterns); err != nil {
		return err
	} else if httpCode == 404 && patternOrg != "" && pattern != "" {
		return cliutils.CLIError{StatusCode: cliutils.NOT_FOUND, i18n.GetMessagePrinter().Sprintf("pattern '%s' with org '%s' and node org '%s' not found in agbot '%s'", pattern, patternOrg, nodeOrg, agbot))
	}
	output, err := cliutils.MarshalIndent(patterns.Patterns, "exchange agbot listpattern")
	if err != nil {
		return err
	}
	fmt.Println(output)

	return nil
}

type ServedPattern struct {
	PatternOrg string `json:"patternOrgid"`
	Pattern    string `json:"pattern"`
	NodeOrg    string `json:"nodeOrgid"`
}

func AgbotAddPattern(org, userPw, agbot, patternOrg, pattern, nodeOrg string, exchangeHandler cliutils.ServiceHandler) error {
	cliutils.SetWhetherUsingApiKey(userPw)
	var agbotOrg string
	var err error
	if agbotOrg, agbot, err = cliutils.TrimOrg(org, agbot); err != nil {
		return err
	}
	if nodeOrg == "" {
		nodeOrg = patternOrg
	}
	input := ServedPattern{PatternOrg: patternOrg, Pattern: pattern, NodeOrg: nodeOrg}
	if httpCode, err := exchangeHandler.Post("orgs/"+agbotOrg+"/agbots/"+agbot+"/patterns", cliutils.OrgAndCreds(org, userPw), input, nil); err != nil {
		return err
	} else if httpCode == 409 {
		i18n.GetMessagePrinter().Printf("Pattern '%s' with org '%s' and node org '%s' already exists in agbot '%s'", pattern, patternOrg, nodeOrg, agbot)
		i18n.GetMessagePrinter().Println()
		os.Exit(cliutils.CLI_INPUT_ERROR)
	}

	return nil
}

func AgbotRemovePattern(org, userPw, agbot, patternOrg, pattern, nodeOrg string, exchangeHandler cliutils.ServiceHandler) error {
	cliutils.SetWhetherUsingApiKey(userPw)
	var agbotOrg string
	var err error
	if agbotOrg, agbot, err = cliutils.TrimOrg(org, agbot); err != nil {
		return err
	}
	if nodeOrg == "" {
		nodeOrg = patternOrg
	}
	patternId := formServicedObjectId(patternOrg, pattern, nodeOrg)
	if _, err = exchangeHandler.Delete("orgs/"+agbotOrg+"/agbots/"+agbot+"/patterns/"+patternId, cliutils.OrgAndCreds(org, userPw)); err != nil {
		return err
	}

	return nil
}

type ServedBusinessPolicy struct {
	BusinessPolOrg string `json:"businessPolOrgid"` // defaults to nodeOrgid
	BusinessPol    string `json:"businessPol"`      // '*' means all
	NodeOrg        string `json:"nodeOrgid"`
	LastUpdated    string `json:"lastUpdated,omitempty"`
}

func AgbotListBusinessPolicy(org, userPw, agbot string, exchangeHandler cliutils.ServiceHandler) error {
	cliutils.SetWhetherUsingApiKey(userPw)
	var agbotOrg string
	var err error
	if agbotOrg, agbot, err = cliutils.TrimOrg(org, agbot); err != nil {
		return err
	}
	// Display the full resources
	resp := new(exchange.GetAgbotsBusinessPolsResponse)
	if _, err = exchangeHandler.Get("orgs/"+agbotOrg+"/agbots/"+agbot+"/businesspols", cliutils.OrgAndCreds(org, userPw), resp); err != nil {
		return err
	}
	output, err := cliutils.MarshalIndent(resp.BusinessPols, "exchange agbot listbusinesspol")
	if err != nil {
		return err
	}
	fmt.Println(output)

	return nil
}

// Add the business policy to the agot supporting list. Currently
// all the patterns are open to all the nodes within the same organization.
func AgbotAddBusinessPolicy(org, userPw, agbot, polOrg string, exchangeHandler cliutils.ServiceHandler) error {
	cliutils.SetWhetherUsingApiKey(userPw)
	var agbotOrg string
	var err error
	if agbotOrg, agbot, err = cliutils.TrimOrg(org, agbot); err != nil {
		return err
	}

	input := exchange.ServedBusinessPolicy{BusinessPolOrg: polOrg, BusinessPol: "*", NodeOrg: polOrg}
	i18n.GetMessagePrinter().Printf("Adding Business policy org %s' to agbot '%s'. The agbot will start looking for nodes that are compatible with this policy.", polOrg, agbot)
	i18n.GetMessagePrinter().Println()
	if httpCode, err := exchangeHandler.Post("orgs/"+agbotOrg+"/agbots/"+agbot+"/businesspols", cliutils.OrgAndCreds(org, userPw), input, nil); err != nil {
		return err
	} else if httpCode == 409 {
		i18n.GetMessagePrinter().Printf("Business policy org %s' already exists in agbot '%s'", polOrg, agbot)
		i18n.GetMessagePrinter().Println()
		os.Exit(cliutils.CLI_INPUT_ERROR)
	}
	
	return nil
}

// Remove the business policy from the agot supporting list. Currently
// only supporting removing all the policies from a organization.
func AgbotRemoveBusinessPolicy(org, userPw, agbot, PolOrg string, exchangeHandler cliutils.ServiceHandler) error {
	cliutils.SetWhetherUsingApiKey(userPw)
	var agbotOrg string
	var err error
	if agbotOrg, agbot, err = cliutils.TrimOrg(org, agbot); err != nil {
		return err
	}
	polId := formServicedObjectId(PolOrg, "*", PolOrg)
	i18n.GetMessagePrinter().Printf("Removing Business policy org %s' to agbot '%s'. The agbot is no longer looking for nodes that are compatible with this policy.", PolOrg, agbot)
	i18n.GetMessagePrinter().Println()
	if _, err = exchangeHandler.Delete("orgs/"+agbotOrg+"/agbots/"+agbot+"/businesspols/"+polId, cliutils.OrgAndCreds(org, userPw)); err != nil {
		return err
	}

	return nil
}
