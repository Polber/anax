package deploycheck

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/open-horizon/anax/businesspolicy"
	"github.com/open-horizon/anax/cli/cliconfig"
	"github.com/open-horizon/anax/cli/cliutils"
	"github.com/open-horizon/anax/common"
	"github.com/open-horizon/anax/compcheck"
	"github.com/open-horizon/anax/exchange"
	"github.com/open-horizon/anax/i18n"
	"github.com/open-horizon/anax/policy"
	"github.com/open-horizon/anax/semanticversion"
	"os"
)

func readServiceFile(filePath string, inputFileStruct *common.ServiceFile) error {
	newBytes, err := cliconfig.ReadJsonFileWithLocalConfig(filePath)
	if err != nil {
		return err
	}
	err = json.Unmarshal(newBytes, inputFileStruct)
	if err != nil {
		return cliutils.CLIError{StatusCode: cliutils.JSON_PARSING_ERROR, Message: i18n.GetMessagePrinter().Sprintf("Error unmarshaling service json file %s: %v", filePath, err)}
	}

	return nil
}

func readUserInputFile(filePath string, inputFileStruct *[]policy.UserInput) error {
	newBytes, err := cliconfig.ReadJsonFileWithLocalConfig(filePath)
	if err != nil {
		return err
	}
	err = json.Unmarshal(newBytes, inputFileStruct)
	if err != nil {
		return cliutils.CLIError{StatusCode: cliutils.JSON_PARSING_ERROR, Message: i18n.GetMessagePrinter().Sprintf("Error unmarshaling userInput json file: %v", err)}
	}

	return nil
}

// check if the user inputs for services are compatible
func UserInputCompatible(org string, userPw string, nodeId string, nodeArch string, nodeType string, nodeUIFile string,
	businessPolId string, businessPolFile string, patternId string, patternFile string,
	svcDefFiles []string, checkAllSvcs bool, showDetail bool, exchangeHandler cliutils.ServiceHandler) error {

	msgPrinter := i18n.GetMessagePrinter()

	// check the input and get the defaults
	userOrg, credToUse, nId, useNodeId, bp, pattern, serviceDefs, err := verifyUserInputCompatibleParameters(
		org, userPw, nodeId, nodeType, nodeUIFile, businessPolId, businessPolFile, patternId, patternFile, svcDefFiles, exchangeHandler)
	if err != nil {
		return err
	}

	uiCheckInput := compcheck.UserInputCheck{}
	uiCheckInput.NodeArch = nodeArch
	uiCheckInput.NodeType = nodeType
	uiCheckInput.BusinessPolicy = bp
	uiCheckInput.PatternId = patternId
	uiCheckInput.Pattern = pattern

	// use the user org for the patternId if it does not include an org id
	if uiCheckInput.PatternId != "" {
		if uiCheckInput.PatternId, err = cliutils.AddOrg(userOrg, uiCheckInput.PatternId); err != nil {
			return err
		}
	}

	// formalize node id or get node user input
	bUseLocalNode := false
	if useNodeId {
		// add credentials'org to node id if the node id does not have an org
		if nId, err = cliutils.AddOrg(userOrg, nId); err != nil {
			return err
		}
		uiCheckInput.NodeId = nId
	} else if nodeUIFile != "" {
		// read the node userinput from file
		var node_ui []policy.UserInput
		readUserInputFile(nodeUIFile, &node_ui)
		uiCheckInput.NodeUserInput = node_ui
	} else {
		msgPrinter.Printf("Neither node id nor node user input file is specified. Getting node user input from the local node.")
		msgPrinter.Println()
		bUseLocalNode = true
	}

	if bUseLocalNode {
		// get id from local node, check arch
		if uiCheckInput.NodeId, uiCheckInput.NodeArch, uiCheckInput.NodeType, _, err = getLocalNodeInfo(nodeArch, nodeType, ""); err != nil {
			return err
		}

		// get node user input from local node
		var node_ui []policy.UserInput
		cliutils.HorizonGet("node/userinput", []int{200}, &node_ui, false)
		uiCheckInput.NodeUserInput = node_ui
	}

	if nodeType == "" && uiCheckInput.NodeId != "" {
		cliutils.Verbose(msgPrinter.Sprintf("No node type has been provided: node type of '%v' node will be used", uiCheckInput.NodeId))
	}

	// put the given service defs into the uiCheckInput
	if serviceDefs != nil || len(serviceDefs) != 0 {
		uiCheckInput.Service = serviceDefs
	}

	cliutils.Verbose(msgPrinter.Sprintf("Using compatibility checking input: %v", uiCheckInput))

	// get exchange context
	ec, err := cliutils.GetUserExchangeContext(userOrg, credToUse)
	if err != nil {
		return err
	}

	// compcheck.UserInputCompatible function calls the exchange package that calls glog.
	// set the glog stderrthreshold to 3 (fatal) in order for glog error messages not showing up in the output
	flag.Set("stderrthreshold", "3")

	// now we can call the real code to check if the policies are compatible.
	// the policy validation are done wthin the calling function.
	compOutput, err := compcheck.UserInputCompatible(ec, &uiCheckInput, checkAllSvcs, msgPrinter)
	if err != nil {
		return cliutils.CLIError{StatusCode: cliutils.CLI_GENERAL_ERROR, Message: err.Error()}
	} else {
		if !showDetail {
			compOutput.Input = nil
		}

		// display the output
		output, err := cliutils.DisplayAsJson(compOutput)
		if err != nil {
			return cliutils.CLIError{StatusCode: cliutils.JSON_PARSING_ERROR, Message: msgPrinter.Sprintf("failed to marshal 'hzn deploycheck userinput' output: %v", err)}
		}

		fmt.Println(output)
	}

	return nil
}

// Make sure the url, arch and version are correct in the service definition file.
func validateService(service common.AbstractServiceFile) error {
	msgPrinter := i18n.GetMessagePrinter()

	if service.GetURL() == "" {
		return fmt.Errorf(msgPrinter.Sprintf("URL must be specified in the service definition."))
	}
	if service.GetVersion() == "" {
		return fmt.Errorf(msgPrinter.Sprintf("Version must be specified in the service definition."))
	} else if !semanticversion.IsVersionString(service.GetVersion()) {
		return fmt.Errorf(msgPrinter.Sprintf("Invalid version format: %v.", service.GetVersion()))
	}
	if service.GetArch() == "" {
		return fmt.Errorf(msgPrinter.Sprintf("Arch must be specified in the service definition."))
	}

	return nil
}

// Make sure -n and --node-ui, -b and -B
// and -p and -P pairs are mutually exclusive.
// Business policy and pattern are mutually exclusive.
// Get default credential, node id and org if they are not set.
func verifyUserInputCompatibleParameters(org string, userPw string, nodeId string, nodeType string, nodeUIFile string,
	businessPolId string, businessPolFile string, patternId string, patternFile string,
	svcDefFiles []string, exchangeHandler cliutils.ServiceHandler) (string, string, string, bool, *businesspolicy.BusinessPolicy, common.AbstractPatternFile, []common.AbstractServiceFile, error) {

	// get message printer
	msgPrinter := i18n.GetMessagePrinter()

	// make sure the node type has correct value
	ValidateNodeType(nodeType)

	useNodeId := false
	nodeIdToUse := nodeId
	if nodeId != "" {
		if nodeUIFile == "" {
			// true means will use exchange call
			useNodeId = true
		} else {
			return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, Message: msgPrinter.Sprintf("-n and --node-ui are mutually exclusive.")}
		}
	} else {
		if nodeUIFile == "" {
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

	// make sure only specify one: business policy or pattern
	useBPol := false
	if businessPolId != "" || businessPolFile != "" {
		useBPol = true
		if patternId != "" || patternFile != "" {
			return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, Message: msgPrinter.Sprintf("Please specify either deployment policy or pattern.")}
		}
	} else {
		if patternId == "" && patternFile == "" {
			return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, Message: msgPrinter.Sprintf("One of these flags must be specified: -b, -B, -p, or -P.")}
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
				return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, Message: msgPrinter.Sprintf("-b and -B are mutually exclusive.")}
			}
		}
	} else {
		if patternId != "" {
			if patternFile == "" {
				// true means will use exchange call
				usePatternId = true
			} else {
				return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, Message: msgPrinter.Sprintf("-p and -P are mutually exclusive.")}
			}
		}
	}

	useSId, serviceDefs := useExchangeForServiceDef(svcDefFiles)

	// if user credential is not given, then use the node auth env HZN_EXCHANGE_NODE_AUTH if it is defined.
	var err error
	credToUse := cliutils.WithDefaultEnvVar(&userPw, "HZN_EXCHANGE_NODE_AUTH")
	orgToUse := org
	if useNodeId || useBPolId || usePatternId || useSId {
		if *credToUse == "" {
			return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, Message: msgPrinter.Sprintf("Please specify the Exchange credential with -u for querying the node, deployment policy and service policy.")}
		} else {
			// get the org from credToUse
			if org == "" {
				id, _ := cliutils.SplitIdToken(*credToUse)
				if id != "" {
					if orgToUse, _, err = cliutils.TrimOrg("", id); err != nil {
						return "", "", "", false, nil, nil, nil, err
					}
					if orgToUse == "" {
						return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, Message: msgPrinter.Sprintf("Please specify the organization with -o for the Exchange credentials: %v.", *credToUse)}
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

// Given a service definition files, check if the exchange call will be needed to get all the dependent services.
// It also returns the service definitions from the files and an array of service orgs.
func useExchangeForServiceDef(svcDefFiles []string) (bool, []common.AbstractServiceFile) {
	// get message printer
	msgPrinter := i18n.GetMessagePrinter()

	useSId := false
	serviceDefs := []common.AbstractServiceFile{}

	if svcDefFiles == nil || len(svcDefFiles) == 0 {
		// true means will use exchange call
		useSId = true
	} else {
		// check if the service has dependent services, if it does, then the code needs to
		// access the exchange
		for _, s_file := range svcDefFiles {
			var service common.ServiceFile
			readServiceFile(s_file, &service)
			if err := validateService(&service); err != nil {
				return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, Message: msgPrinter.Sprintf("Error in service file %v. %v", s_file, err)}
			}

			serviceDefs = append(serviceDefs, &service)

			if service.HasDependencies() {
				// true means will use exchange call
				useSId = true
			}
		}
	}

	return useSId, serviceDefs
}

// get pattern from exchange or from file.
func getPattern(defaultOrg string, credToUse string, patternId string, patternFile string, exchangeHandler cliutils.ServiceHandler) (common.AbstractPatternFile, error) {
	// get message printer
	msgPrinter := i18n.GetMessagePrinter()

	if patternFile != "" {
		var pf common.PatternFile
		// get pattern from file
		newBytes, err := cliconfig.ReadJsonFileWithLocalConfig(patternFile)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(newBytes, &pf); err != nil {
			return cliutils.CLIError{StatusCode: cliutils.JSON_PARSING_ERROR, Message: msgPrinter.Sprintf("failed to unmarshal pattern json input file %s: %v", patternFile, err)}
		}
		return &pf, nil
	} else {
		var pe compcheck.Pattern
		// get pattern from the exchange
		var patternList exchange.GetPatternResponse
		patOrg, patId, err := cliutils.TrimOrg(defaultOrg, patternId)
		if err != nil {
			return nil, err
		}

		if httpCode, err := exchangeHandler.Get("orgs/"+patOrg+"/patterns"+cliutils.AddSlash(patId), cliutils.OrgAndCreds(defaultOrg, credToUse), &patternList); err != nil {
			return nil, err
		} else if httpCode == 404 || patternList.Patterns == nil || len(patternList.Patterns) == 0 {
			return cliutils.CLIError{StatusCode: cliutils.NOT_FOUND, Message: msgPrinter.Sprintf("Pattern not found for %v/%v", patOrg, patId)}
		} else {
			for _, exchPat := range patternList.Patterns {
				pe = compcheck.Pattern{Org: patOrg, Pattern: exchPat}
				return &pe, nil
			}
		}
	}
	return nil, nil
}

// make sure the service defs matches the required top level services for pattern
func checkServiceDefsForPattern(pattern common.AbstractPatternFile, serviceDefs []common.AbstractServiceFile, svcDefFiles []string) {
	// get message printer
	msgPrinter := i18n.GetMessagePrinter()

	// check if the specified the services are the ones that the pattern needs.
	if serviceDefs != nil && len(serviceDefs) != 0 {
		for i, sdef := range serviceDefs {
			found := false
			for _, sref := range pattern.GetServices() {
				if sdef.GetURL() == sref.ServiceURL && (sdef.GetOrg() == "" || sdef.GetOrg() == sref.ServiceOrg) && (sref.ServiceArch == "" || sref.ServiceArch == "*" || sdef.GetArch() == sref.ServiceArch) {
					for _, v := range sref.ServiceVersions {
						if sdef.GetVersion() == v.Version {
							found = true
							break
						}
					}
					if found {
						break
					}
				}
			}

			if !found {
				return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, Message: msgPrinter.Sprintf("The service %v/%v %v %v specified in file %v does not match the pattern requirement.", sdef.GetOrg(), sdef.GetURL(), sdef.GetArch(), sdef.GetVersion(), svcDefFiles[i])}
			}
		}
	}
}

// make sure the service defs matches the required top level services for business policy
func checkServiceDefsForBPol(bp *businesspolicy.BusinessPolicy, serviceDefs []common.AbstractServiceFile, svcDefFiles []string) {
	// get message printer
	msgPrinter := i18n.GetMessagePrinter()

	if svcDefFiles != nil && len(svcDefFiles) != 0 {
		for i, sdef := range serviceDefs {
			found := false
			if sdef.GetURL() == bp.Service.Name && (sdef.GetOrg() == "" || sdef.GetOrg() == bp.Service.Org) && (bp.Service.Arch == "" || bp.Service.Arch == "*" || sdef.GetArch() == bp.Service.Arch) {
				for _, v := range bp.Service.ServiceVersions {
					if sdef.GetVersion() == v.Version {
						found = true
						break
					}
				}
			}
			if !found {
				return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, Message: msgPrinter.Sprintf("The service %v/%v %v %v specified in file %v does not match the deployment policy requirement.", sdef.GetOrg(), sdef.GetURL(), sdef.GetArch(), sdef.GetVersion(), svcDefFiles[i])}
			}
		}
	}
}
