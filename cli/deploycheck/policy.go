package deploycheck

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/open-horizon/anax/cli/cliconfig"
	"github.com/open-horizon/anax/cli/cliutils"
	"github.com/open-horizon/anax/common"
	"github.com/open-horizon/anax/compcheck"
	"github.com/open-horizon/anax/exchangecommon"
	"github.com/open-horizon/anax/i18n"
	"os"
)

func readNodePolicyFile(filePath string, inputFileStruct *exchangecommon.NodePolicy) error {
	newBytes, err := cliconfig.ReadJsonFileWithLocalConfig(filePath)
	if err != nil {
		return err
	}
	err = json.Unmarshal(newBytes, inputFileStruct)
	if err != nil {
		return cliutils.CLIError{StatusCode: cliutils.JSON_PARSING_ERROR, Message: i18n.GetMessagePrinter().Sprintf("failed to unmarshal json input file %s: %v", filePath, err)}
	}

	return nil
}

func readServicePolicyFile(filePath string, inputFileStruct *exchangecommon.ServicePolicy) error {
	newBytes, err := cliconfig.ReadJsonFileWithLocalConfig(filePath)
	if err != nil {
		return err
	}
	err = json.Unmarshal(newBytes, inputFileStruct)
	if err != nil {
		return cliutils.CLIError{StatusCode: cliutils.JSON_PARSING_ERROR, Message: i18n.GetMessagePrinter().Sprintf("failed to unmarshal json input file %s: %v", filePath, err)}
	}

	return nil
}

// check if the policies are compatible
func PolicyCompatible(org string, userPw string, nodeId string, nodeArch string, nodeType string, nodePolFile string, businessPolId string, businessPolFile string, servicePolFile string, svcDefFiles []string, checkAllSvcs bool, showDetail bool, exchangeHandler cliutils.ServiceHandler) error {

	msgPrinter := i18n.GetMessagePrinter()

	// check the input and get the defaults
	userOrg, credToUse, nId, useNodeId, serviceDefs, err := verifyPolicyCompatibleParameters(org, userPw, nodeId, nodeType, nodePolFile, businessPolId, businessPolFile, servicePolFile, svcDefFiles)
	if err != nil {
		return err
	}

	policyCheckInput := compcheck.PolicyCheck{}
	policyCheckInput.NodeArch = nodeArch
	policyCheckInput.NodeType = nodeType

	// formalize node id or get node policy
	bUseLocalNode := false
	if useNodeId {
		// add credentials'org to node id if the node id does not have an org
		if nId, err = cliutils.AddOrg(userOrg, nId); err != nil {
			return err
		}
		policyCheckInput.NodeId = nId
	} else if nodePolFile != "" {
		// read the node policy from file
		var np exchangecommon.NodePolicy
		readNodePolicyFile(nodePolFile, &np)
		policyCheckInput.NodePolicy = &np
	} else {
		msgPrinter.Printf("Neither node id nor node policy is specified. Getting node policy from the local node.")
		msgPrinter.Println()
		bUseLocalNode = true
	}

	if bUseLocalNode {
		// get id from local node, check arch
		if policyCheckInput.NodeId, policyCheckInput.NodeArch, policyCheckInput.NodeType, _, err = getLocalNodeInfo(nodeArch, nodeType, ""); err != nil {
			return err
		}

		// get node policy from local node
		var np exchangecommon.NodePolicy
		cliutils.HorizonGet("node/policy", []int{200}, &np, false)
		policyCheckInput.NodePolicy = &np
	}

	if nodeType == "" && policyCheckInput.NodeId != "" {
		cliutils.Verbose(msgPrinter.Sprintf("No node type has been provided: node type of '%v' node will be used", policyCheckInput.NodeId))
	}

	// get business policy
	bp, err := getBusinessPolicy(userOrg, credToUse, businessPolId, businessPolFile, exchangeHandler)
	if err != nil {
		return err
	}
	policyCheckInput.BusinessPolicy = bp

	if servicePolFile != "" {
		// read the service policy from file
		var sp exchangecommon.ServicePolicy
		readServicePolicyFile(servicePolFile, &sp)

		policyCheckInput.ServicePolicy = sp.GetExternalPolicy()
	}

	// put the given service defs into the uiCheckInput
	if serviceDefs != nil || len(serviceDefs) != 0 {
		// check if the given service files specify correct services.
		// Other parts will be checked later by the compcheck package.
		checkServiceDefsForBPol(bp, serviceDefs, svcDefFiles)

		policyCheckInput.Service = serviceDefs
	}

	cliutils.Verbose(msgPrinter.Sprintf("Using compatibility checking input: %v", policyCheckInput))

	// get exchange context
	ec, err := cliutils.GetUserExchangeContext(userOrg, credToUse)
	if err != nil {
		return err
	}

	// compcheck.PolicyCompatible function calls the exchange package that calls glog.
	// set glog to log to /dev/null so glog errors will not be printed
	flag.Set("log_dir", "/dev/null")

	// now we can call the real code to check if the policies are compatible.
	// the policy validation are done wthin the calling function.
	compOutput, err := compcheck.PolicyCompatible(ec, &policyCheckInput, checkAllSvcs, msgPrinter)
	if err != nil {
		return cliutils.CLIError{StatusCode: cliutils.CLI_GENERAL_ERROR, Message: err.Error()}
	} else {
		if !showDetail {
			compOutput.Input = nil
		}

		// display the output
		output, err := cliutils.DisplayAsJson(compOutput)
		if err != nil {
			return cliutils.CLIError{StatusCode: cliutils.JSON_PARSING_ERROR, Message: msgPrinter.Sprintf("failed to marshal 'hzn deploycheck policy' output: %v", err)}
		}

		fmt.Println(output)
	}

	return nil
}

// make sure -n and --node-pol, -b and -B, pairs are mutually compatible.
// get default credential, node id and org if they are not set.
func verifyPolicyCompatibleParameters(org string, userPw string, nodeId string, nodeType string, nodePolFile string,
	businessPolId string, businessPolFile string, servicePolFile string, svcDefFiles []string) (string, string, string, bool, []common.AbstractServiceFile, error) {
	// get message printer
	msgPrinter := i18n.GetMessagePrinter()

	// make sure the node type has correct value
	ValidateNodeType(nodeType)

	useNodeId := false
	nodeIdToUse := nodeId
	if nodeId != "" {
		if nodePolFile == "" {
			// true means will use exchange call
			useNodeId = true
		} else {
			return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, Message: msgPrinter.Sprintf("-n and --node-pol are mutually exclusive.")}
		}
	} else {
		if nodePolFile == "" {
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
	if businessPolId != "" {
		if businessPolFile == "" {
			// true means will use exchange call
			useBPolId = true
		} else {
			return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, Message: msgPrinter.Sprintf("-b and -B are mutually exclusive.")}
		}
	} else {
		if businessPolFile == "" {
			return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, Message: msgPrinter.Sprintf("Either -b or -B must be specified.")}
		}
	}

	useSPolId := false
	if servicePolFile == "" {
		// true means will use exchange call
		useSPolId = true
	}

	if businessPolId != "" && svcDefFiles != nil && len(svcDefFiles) > 0 {
		return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, Message: msgPrinter.Sprintf("-b and --service are mutually exclusive.")}
	}

	useSId, serviceDefs := useExchangeForServiceDef(svcDefFiles)

	// if user credential is not given, then use the node auth env HZN_EXCHANGE_NODE_AUTH if it is defined.
	var err error
	credToUse := cliutils.WithDefaultEnvVar(&userPw, "HZN_EXCHANGE_NODE_AUTH")
	orgToUse := org
	if useNodeId || useBPolId || useSPolId || useSId {
		if *credToUse == "" {
			return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, Message: msgPrinter.Sprintf("Please specify the Exchange credential with -u for querying the node, deployment policy, service and service policy.")}
		} else {
			// get the org from credToUse
			if org == "" {
				id, _ := cliutils.SplitIdToken(*credToUse)
				if id != "" {
					if orgToUse, _, err = cliutils.TrimOrg("", id); err != nil {
						return "", "", "", false, nil, err
					}
					if orgToUse == "" {
						return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, Message: msgPrinter.Sprintf("Please specify the organization with -o for the Exchange credentials: %v.", *credToUse)}
					}
				}
			}
		}
	}

	return orgToUse, *credToUse, nodeIdToUse, useNodeId, serviceDefs, nil
}
