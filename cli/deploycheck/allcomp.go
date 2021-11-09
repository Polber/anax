package deploycheck

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/open-horizon/anax/api"
	"github.com/open-horizon/anax/businesspolicy"
	"github.com/open-horizon/anax/cli/cliconfig"
	"github.com/open-horizon/anax/cli/cliutils"
	"github.com/open-horizon/anax/common"
	"github.com/open-horizon/anax/compcheck"
	"github.com/open-horizon/anax/cutil"
	"github.com/open-horizon/anax/exchange"
	"github.com/open-horizon/anax/exchangecommon"
	"github.com/open-horizon/anax/i18n"
	"github.com/open-horizon/anax/persistence"
	"github.com/open-horizon/anax/policy"
	"os"
)

// check if the policies are compatible
func AllCompatible(org string, userPw string, nodeId string, nodeArch string, nodeType string, nodeOrg string,
	nodePolFile string, nodeUIFile string, businessPolId string, businessPolFile string,
	patternId string, patternFile string, servicePolFile string, svcDefFiles []string,
	checkAllSvcs bool, showDetail bool, exchangeHandler cliutils.ServiceHandler) error {

	msgPrinter := i18n.GetMessagePrinter()

	// check the input and get the defaults
	userOrg, credToUse, nId, useNodeId, bp, pattern, serviceDefs, err := verifyCompCheckParameters(
		org, userPw, nodeId, nodeType, nodePolFile, nodeUIFile, businessPolId, businessPolFile,
		patternId, patternFile, servicePolFile, svcDefFiles, exchangeHandler)
	if err != nil {
		return err
	}

	compCheckInput := compcheck.CompCheck{}
	compCheckInput.NodeArch = nodeArch
	compCheckInput.NodeType = nodeType
	compCheckInput.NodeOrg = nodeOrg
	compCheckInput.BusinessPolicy = bp
	compCheckInput.PatternId = patternId
	compCheckInput.Pattern = pattern

	// use the user org for the patternId if it does not include an org id
	if compCheckInput.PatternId != "" {
		if compCheckInput.PatternId, err = cliutils.AddOrg(userOrg, compCheckInput.PatternId); err != nil {
			return err
		}
	}

	if useNodeId {
		// add credentials'org to node id if the node id does not have an org
		if nId, err = cliutils.AddOrg(userOrg, nId); err != nil {
			return err
		}
		compCheckInput.NodeId = nId
	}

	// formalize node id or get node policy
	bUseLocalNodeForPolicy := false
	bUseLocalNodeForUI := false
	if bp != nil || pattern != nil || patternId != "" {
		if nodePolFile != "" {
			// read the node policy from file
			var np exchangecommon.NodePolicy
			readNodePolicyFile(nodePolFile, &np)
			compCheckInput.NodePolicy = &np
		} else if !useNodeId {
			bUseLocalNodeForPolicy = true
		}
	}

	if nodeUIFile != "" {
		// read the node userinput from file
		var node_ui []policy.UserInput
		readUserInputFile(nodeUIFile, &node_ui)
		compCheckInput.NodeUserInput = node_ui
	} else if !useNodeId {
		bUseLocalNodeForUI = true
	}

	if bUseLocalNodeForPolicy {
		msgPrinter.Printf("Neither node id nor node policy is specified. Getting node policy from the local node.")
		msgPrinter.Println()

		// get node policy from local node
		var np exchangecommon.NodePolicy
		cliutils.HorizonGet("node/policy", []int{200}, &np, false)
		compCheckInput.NodePolicy = &np
	}

	if bUseLocalNodeForUI {
		msgPrinter.Printf("Neither node id nor node user input file is specified. Getting node user input from the local node.")
		msgPrinter.Println()
		// get node user input from local node
		var node_ui []policy.UserInput
		cliutils.HorizonGet("node/userinput", []int{200}, &node_ui, false)
		compCheckInput.NodeUserInput = node_ui
	}

	if bUseLocalNodeForPolicy || bUseLocalNodeForUI {
		// get id from local node, check arch
		if compCheckInput.NodeId, compCheckInput.NodeArch, compCheckInput.NodeType, compCheckInput.NodeOrg, err = getLocalNodeInfo(nodeArch, nodeType, nodeOrg); err != nil {
			return err
		}
	}

	if nodeType == "" && compCheckInput.NodeId != "" {
		cliutils.Verbose(msgPrinter.Sprintf("No node type has been provided: node type of '%v' node will be used", compCheckInput.NodeId))
	}

	// read the service policy from file for the policy case
	if servicePolFile != "" {
		var sp exchangecommon.ServicePolicy
		readServicePolicyFile(servicePolFile, &sp)
		compCheckInput.ServicePolicy = sp.GetExternalPolicy()
	}

	// put the given service defs into the compCheckInput
	if serviceDefs != nil || len(serviceDefs) != 0 {
		compCheckInput.Service = serviceDefs
	}

	cliutils.Verbose(msgPrinter.Sprintf("Using compatibility checking input: %v", compCheckInput))

	// get exchange context
	ec, err := cliutils.GetUserExchangeContext(userOrg, credToUse)
	if err != nil {
		return err
	}
	agbotUrl := cliutils.GetAgbotSecureAPIUrlBase()

	// compcheck.Compatible function calls the exchange package that calls glog.
	// set glog to log to /dev/null so glog errors will not be printed
	flag.Set("log_dir", "/dev/null")

	// now we can call the real code to check if the policies are compatible.
	// the policy validation are done wthin the calling function.
	compOutput, err := compcheck.DeployCompatible(ec, agbotUrl, &compCheckInput, checkAllSvcs, msgPrinter)
	if err != nil {
		return cliutils.CLIError{StatusCode: cliutils.CLI_GENERAL_ERROR, Message: err.Error()}
	} else {
		if !showDetail {
			compOutput.Input = nil
		}

		// display the output
		output, err := cliutils.DisplayAsJson(compOutput)
		if err != nil {
			return cliutils.CLIError{StatusCode: cliutils.JSON_PARSING_ERROR, Message: msgPrinter.Sprintf("failed to marshal 'hzn deploycheck all' output: %v", err)}
		}

		fmt.Println(output)
	}

	return nil
}

// Make sure -n and --node-pol, -b and -B pairs
// and -p and -P pairs are mutually exclusive.
// Business policy and pattern are mutually exclusive.
// Get default credential, node id and org if they are not set.
func verifyCompCheckParameters(org string, userPw string, nodeId string, nodeType string, nodePolFile string, nodeUIFile string,
	businessPolId string, businessPolFile string, patternId string, patternFile string, servicePolFile string,
	svcDefFiles []string, exchangeHandler cliutils.ServiceHandler) (string, string, string, bool, *businesspolicy.BusinessPolicy, common.AbstractPatternFile, []common.AbstractServiceFile, error) {

	// get message printer
	msgPrinter := i18n.GetMessagePrinter()

	var err error

	// make sure the node type has correct value
	ValidateNodeType(nodeType)

	// make sure only specify one: business policy or pattern
	useBPol := false
	if businessPolId != "" || businessPolFile != "" {
		useBPol = true
		if patternId != "" || patternFile != "" {
			return "", "", "", false, nil, nil, nil, cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, Message: msgPrinter.Sprintf("Please specify either deployment policy or pattern.")}
		}
	} else {
		if patternId == "" && patternFile == "" {
			return "", "", "", false, nil, nil, nil, cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, Message: msgPrinter.Sprintf("One of these flags must be specified: -b, -B, -p, or -P.")}
		}
	}

	useNodeId := false
	nodeIdToUse := nodeId
	if nodeId != "" {
		if (useBPol && nodePolFile == "") || (!useBPol && nodeUIFile == "") {
			// true means will use exchange call
			useNodeId = true
		}
		if nodePolFile != "" {
			return "", "", "", false, nil, nil, nil, cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, Message: msgPrinter.Sprintf("-n and --node-pol are mutually exclusive.")}
		}
		if nodeUIFile != "" {
			return "", "", "", false, nil, nil, nil, cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, Message: msgPrinter.Sprintf("-n and --node-ui are mutually exclusive.")}
		}
	} else {
		if (useBPol && nodePolFile == "") || (!useBPol && nodeUIFile == "") {
			// get node id from HZN_EXCHANGE_NODE_AUTH
			if nodeIdTok := os.Getenv("HZN_EXCHANGE_NODE_AUTH"); nodeIdTok != "" {
				nodeIdToUse, _ = cliutils.SplitIdToken(nodeIdTok)
				if nodeIdToUse != "" {
					// true means will use exchange call
					useNodeId = true
				}
			}
		}
	}

	useBPolId := false
	usePatternId := false
	if useBPol {
		if businessPolId != "" {
			if businessPolFile == "" {
				// true means will use exchange call
				useBPolId = true
			} else {
				return "", "", "", false, nil, nil, nil, cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, Message: msgPrinter.Sprintf("-b and -B are mutually exclusive.")}
			}
		}
	} else {
		if patternId != "" {
			if patternFile == "" {
				// true means will use exchange call
				usePatternId = true
			} else {
				return "", "", "", false, nil, nil, nil, cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, Message: msgPrinter.Sprintf("-p and -P are mutually exclusive.")}
			}
		}
	}

	useSPolId := false
	if servicePolFile == "" {
		// true means will use exchange call
		useSPolId = true
	}

	useSId, serviceDefs := useExchangeForServiceDef(svcDefFiles)

	// if user credential is not given, then use the node auth env HZN_EXCHANGE_NODE_AUTH if it is defined.
	credToUse := cliutils.WithDefaultEnvVar(&userPw, "HZN_EXCHANGE_NODE_AUTH")
	orgToUse := org
	if useNodeId || useBPolId || useSPolId || usePatternId || useSId {
		if *credToUse == "" {
			return "", "", "", false, nil, nil, nil, cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, Message: msgPrinter.Sprintf("Please specify the Exchange credential with -u for querying the node, deployment policy and service policy.")}
		} else {
			// get the org from credToUse
			if org == "" {
				id, _ := cliutils.SplitIdToken(*credToUse)
				if id != "" {
					if orgToUse, _, err = cliutils.TrimOrg("", id); err != nil {
						return "", "", "", false, nil, nil, nil, err
					}
					if orgToUse == "" {
						return "", "", "", false, nil, nil, nil, cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, Message: msgPrinter.Sprintf("Please specify the organization with -o for the Exchange credentials: %v.", *credToUse)}
					}
				}
			}
		}
	}

	if useBPol {
		// get business policy from file or exchange
		bp, err := getBusinessPolicy(orgToUse, *credToUse, businessPolId, businessPolFile, exchangeHandler)
		if err != nil {
			return "", "", "", false, nil, nil, nil, err
		}
		// the compcheck package does not need to get it again from the exchange.
		useBPolId = false

		// check if the given service files specify correct services.
		// Other parts will be checked later by the compcheck package.
		checkServiceDefsForBPol(bp, serviceDefs, svcDefFiles)

		return orgToUse, *credToUse, nodeIdToUse, useNodeId, bp, nil, serviceDefs, nil
	} else {
		// get pattern from file or exchange
		pattern, err := getPattern(orgToUse, *credToUse, patternId, patternFile, exchangeHandler)
		if err != nil {
			return "", "", "", false, nil, nil, nil, err
		}

		// check if the specified the services are the ones that the pattern needs.
		// only check if the given services are valid or not.
		// Not checking the missing ones becaused it will be checked by the compcheck package.
		checkServiceDefsForPattern(pattern, serviceDefs, svcDefFiles)

		return orgToUse, *credToUse, nodeIdToUse, useNodeId, nil, pattern, serviceDefs, nil
	}
}

// get node info and check node arch and org against the input arch
func getLocalNodeInfo(inputArch string, inputType string, inputOrg string) (string, string, string, string, error) {
	// get message printer
	msgPrinter := i18n.GetMessagePrinter()

	var err error

	id := ""
	nodeType := ""
	nodeOrg := ""
	arch := cutil.ArchString()

	horDevice := api.HorizonDevice{}
	cliutils.HorizonGet("node", []int{200}, &horDevice, false)

	// check node current state
	if horDevice.Config == nil || horDevice.Config.State == nil || *horDevice.Config.State != persistence.CONFIGSTATE_CONFIGURED {
		return "", "", "", "", cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, Message: msgPrinter.Sprintf("Cannot use the local node because it is not registered.")}
	}

	// get node id, type and org
	if horDevice.Org != nil {
		nodeOrg = *horDevice.Org
		if horDevice.Id != nil {
			if id, err = cliutils.AddOrg(*horDevice.Org, *horDevice.Id); err != nil {
				return "", "", "", "", err
			}
		}
	}
	if horDevice.NodeType != nil {
		nodeType = *horDevice.NodeType
	}

	// check node architecture
	if inputArch != "" && inputArch != arch {
		return "", "", "", "", cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, Message: msgPrinter.Sprintf("The node architecture %v specified by -a does not match the architecture of the local node %v.", inputArch, arch)}
	}

	// get/check node architecture
	if inputType != "" && nodeType != "" && inputType != nodeType {
		return "", "", "", "", cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, Message: msgPrinter.Sprintf("The node type %v specified by -t does not match the type of the local node %v.", inputType, nodeType)}
	}

	// check node organization
	if inputOrg != "" && nodeOrg != "" && inputOrg != nodeOrg {
		return "", "", "", "", cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, Message: msgPrinter.Sprintf("The node organization %v specified by -O does not match the organization of the local node %v.", inputType, nodeOrg)}
	}

	return id, arch, nodeType, nodeOrg, nil
}

// get business policy from exchange or from file.
func getBusinessPolicy(defaultOrg string, credToUse string, businessPolId string, businessPolFile string, exchangeHandler cliutils.ServiceHandler) (*businesspolicy.BusinessPolicy, error) {
	// get message printer
	msgPrinter := i18n.GetMessagePrinter()

	var bp businesspolicy.BusinessPolicy
	if businessPolFile != "" {
		// get business policy from file
		newBytes, err := cliconfig.ReadJsonFileWithLocalConfig(businessPolFile)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(newBytes, &bp); err != nil {
			return nil, cliutils.CLIError{StatusCode: cliutils.JSON_PARSING_ERROR, Message: msgPrinter.Sprintf("failed to unmarshal deployment policy json input file %s: %v", businessPolFile, err)}
		}
	} else {
		// get business policy from the exchange
		var policyList exchange.GetBusinessPolicyResponse
		polOrg, polId, err := cliutils.TrimOrg(defaultOrg, businessPolId)
		if err != nil  {
			return nil, err
		}

		httpCode, err := exchangeHandler.Get("orgs/"+polOrg+"/business/policies"+cliutils.AddSlash(polId), cliutils.OrgAndCreds(defaultOrg, credToUse), &policyList)
		if err != nil {
			return nil, err
		}
		if httpCode == 404 || policyList.BusinessPolicy == nil || len(policyList.BusinessPolicy) == 0 {
			return nil, cliutils.CLIError{StatusCode: cliutils.NOT_FOUND, Message: msgPrinter.Sprintf("Deployment policy not found for %v/%v", polOrg, polId)}
		} else {
			for _, exchPol := range policyList.BusinessPolicy {
				bp = exchPol.GetBusinessPolicy()
				break
			}
		}
	}
	return &bp, nil
}

// make sure that the node type has correct value.
func ValidateNodeType(nodeType string) error {
	// get message printer
	msgPrinter := i18n.GetMessagePrinter()

	if nodeType != "" && nodeType != persistence.DEVICE_TYPE_DEVICE && nodeType != persistence.DEVICE_TYPE_CLUSTER {
		return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, Message: msgPrinter.Sprintf("Wrong node type specified: %v. It must be 'device' or 'cluster'.", nodeType)}
	}

	return nil
}
