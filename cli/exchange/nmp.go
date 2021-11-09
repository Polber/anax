package exchange

import (
	"encoding/json"
	"fmt"
	"github.com/open-horizon/anax/cli/cliconfig"
	"github.com/open-horizon/anax/cli/cliutils"
	"github.com/open-horizon/anax/exchange"
	"github.com/open-horizon/anax/exchangecommon"
	"github.com/open-horizon/anax/i18n"
)

func NMPList(org, credToUse, nmpName string, namesOnly bool, exHandler cliutils.ServiceHandler) error {
	cliutils.SetWhetherUsingApiKey(credToUse)

	var nmpOrg string
	var err error
	if nmpOrg, nmpName, err = cliutils.TrimOrg(org, nmpName); err != nil {
		return err
	}

	if nmpName == "*" {
		nmpName = ""
	}

	// get message printer
	msgPrinter := i18n.GetMessagePrinter()

	var nmpList exchange.ExchangeNodeManagementPolicyResponse
	if httpCode, err := exHandler.Get("orgs/"+nmpOrg+"/managementpolicies"+cliutils.AddSlash(nmpName), cliutils.OrgAndCreds(org, credToUse), &nmpList); err != nil {
		return err
	} else if httpCode == 401 {
		user, _ := cliutils.SplitIdToken(credToUse)
		if nmpName == "" {
			return cliutils.CLIError{StatusCode: cliutils.HTTP_ERROR, Message: msgPrinter.Sprintf("Invalid credentials. User \"%s\" cannot access nmp \"%s\" in org \"%s\" with given credentials.\n", user, nmpName, nmpOrg)}
		} else {
			return cliutils.CLIError{StatusCode: cliutils.HTTP_ERROR, Message: msgPrinter.Sprintf("Invalid credentials. User \"%s\" cannot access nmp's in org \"%s\" with given credentials.\n", user, nmpOrg)}
		}
	} else if httpCode == 404 && nmpName != "" {
		return cliutils.CLIError{StatusCode: cliutils.NOT_FOUND, Message: msgPrinter.Sprintf("NMP %s not found in org %s", nmpName, nmpOrg)}
	} else if httpCode == 404 {
		policyNameList := []string{}
		fmt.Println(policyNameList)
	} else if namesOnly && nmpName == "" {
		nmpNameList := []string{}
		for nmp := range nmpList.Policies {
			nmpNameList = append(nmpNameList, nmp)
		}
		jsonBytes, err := json.MarshalIndent(nmpNameList, "", cliutils.JSON_INDENT)
		if err != nil {
			return cliutils.CLIError{StatusCode: cliutils.JSON_PARSING_ERROR, Message: msgPrinter.Sprintf("failed to marshal 'hzn exchange nmp list' output: %v", err)}
		}
		fmt.Println(string(jsonBytes))
	} else {
		if output, err := cliutils.MarshalIndent(nmpList.Policies, "exchange nmp list"); err != nil {
			return err
		} else {
			fmt.Println(output)
		}
	}

	return nil
}

func NMPNew() error {
	// get message printer
	msgPrinter := i18n.GetMessagePrinter()

	var nmp_template = []string{
		`{`,
		`  "label": "",                               /* ` + msgPrinter.Sprintf("A short description of the policy.") + ` */`,
		`  "description": "",                         /* ` + msgPrinter.Sprintf("(Optional) A much longer description of the policy.") + ` */`,
		`  "properties": [                            /* ` + msgPrinter.Sprintf("(Optional) A list of policy properties that describe this policy.") + ` */`,
		`    {`,
		`      "name": "",`,
		`      "value": null`,
		`    }`,
		`  ],`,
		`  "constraints": [                           /* ` + msgPrinter.Sprintf("(Optional) A list of constraint expressions of the form <property name> <operator> <property value>,") + ` */`,
		`    "myproperty == myvalue"                  /* ` + msgPrinter.Sprintf("separated by boolean operators AND (&&) or OR (||).") + `*/`,
		`  ],`,
		`  "patterns": [                              /* ` + msgPrinter.Sprintf("(Optional) This policy applies to nodes using one of these patterns.") + ` */`,
		`    ""`,
		`  ],`,
		`  "enabled": false,                          /* ` + msgPrinter.Sprintf("Is this policy enabled or disabled.") + ` */`,
		`  "agentUpgradePolicy": {                    /* ` + msgPrinter.Sprintf("(Optional) Assertions on how the agent should update itself.") + ` */`,
		`    "atLeastVersion": "<version> | current", /* ` + msgPrinter.Sprintf("Specify the minimum agent version these nodes should have, default \"current\".") + ` */`,
		`    "start": "<RFC3339 timestamp> | now",    /* ` + msgPrinter.Sprintf("When to start an upgrade, default \"now\".") + ` */`,
		`    "duration": 0                            /* ` + msgPrinter.Sprintf("Enable agents to randomize upgrade start time within start + duration, default 0.") + ` */`,
		`  }`,
		`}`,
	}

	for _, s := range nmp_template {
		fmt.Println(s)
	}

	return nil
}

func NMPAdd(org, credToUse, nmpName, jsonFilePath string, noConstraints bool, exHandler cliutils.ServiceHandler) error {
	cliutils.SetWhetherUsingApiKey(credToUse)
	var nmpOrg string
	var err error
	if nmpOrg, nmpName, err = cliutils.TrimOrg(org, nmpName); err != nil {
		return err
	}

	// get message printer
	msgPrinter := i18n.GetMessagePrinter()

	// read in the new nmp from file
	newBytes, err := cliconfig.ReadJsonFileWithLocalConfig(jsonFilePath)
	if err != nil {
		return err
	}
	var nmpFile exchangecommon.ExchangeNodeManagementPolicy
	err = json.Unmarshal(newBytes, &nmpFile)
	if err != nil {
		return cliutils.CLIError{StatusCode: cliutils.JSON_PARSING_ERROR, msgPrinter.Sprintf("failed to unmarshal json input file %s: %v", jsonFilePath, err))
	}

	// validate the format of the nmp
	err = nmpFile.Validate()
	if err != nil {
		return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, msgPrinter.Sprintf("Incorrect node management policy format in file %s: %v", jsonFilePath, err))
	}

	// if the --no-constraints flag is not specified and the given nmp has no constraints, alert the user.
	if (!noConstraints) && nmpFile.HasNoConstraints() {
		return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, msgPrinter.Sprintf("The node management policy has no constraints which might result in the management policy being deployed to all nodes. Please specify --no-constraints to confirm that this is acceptable."))
	}

	var resp struct {
		Code string `json:"code"`
		Msg  string `json:"msg"`
	}
	// add/overwrite nmp file
	if httpCode, err := exHandler.Post("orgs/"+nmpOrg+"/managementpolicies"+cliutils.AddSlash(nmpName), cliutils.OrgAndCreds(org, credToUse), nmpFile, &resp); err != nil {
		return err
	} else if httpCode == 403 {
		//try to update the existing policy
		if httpCode, err = exHandler.Put("orgs/"+nmpOrg+"/managementpolicies"+cliutils.AddSlash(nmpName), cliutils.OrgAndCreds(org, credToUse), nmpFile, nil); err != nil {
			return err
		}
		if httpCode == 201 {
			msgPrinter.Printf("Node management policy: %v/%v updated in the Horizon Exchange", nmpOrg, nmpName)
			msgPrinter.Println()
		} else if httpCode == 404 {
			return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, msgPrinter.Sprintf("Cannot create node management policy %v/%v: %v", nmpOrg, nmpName, resp.Msg))
		}
	} else {
		msgPrinter.Printf("Node management policy: %v/%v added in the Horizon Exchange", nmpOrg, nmpName)
		msgPrinter.Println()
	}

	return nil
}

func NMPRemove(org, credToUse, nmpName string, force bool, exHandler cliutils.ServiceHandler) error {
	cliutils.SetWhetherUsingApiKey(credToUse)
	var nmpOrg string
	var err error
	if nmpOrg, nmpName, err = cliutils.TrimOrg(org, nmpName); err != nil {
		return err
	}

	// get message printer
	msgPrinter := i18n.GetMessagePrinter()

	if !force {
		cliutils.ConfirmRemove(msgPrinter.Sprintf("Are you sure you want to remove node management policy %v for org %v from the Horizon Exchange?", nmpName, nmpOrg))
	}

	//remove policy
	if httpCode, err := exHandler.Delete("orgs/"+nmpOrg+"/managementpolicies"+cliutils.AddSlash(nmpName), cliutils.OrgAndCreds(org, credToUse)); err != nil {
		return err
	} else if httpCode == 404 {
		return cliutils.CLIError{StatusCode: cliutils.NOT_FOUND, msgPrinter.Sprintf("Node management policy %s not found in org %s", nmpName, nmpOrg))
	} else if httpCode == 204 {
		msgPrinter.Printf("Removing node management policy %v/%v and re-evaluating all agreements. Existing agreements might be cancelled and re-negotiated", nmpOrg, nmpName)
		msgPrinter.Println()
		msgPrinter.Printf("Node management policy %v/%v removed", nmpOrg, nmpName)
		msgPrinter.Println()
	}

	return nil
}
