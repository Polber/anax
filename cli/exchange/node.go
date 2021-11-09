package exchange

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/open-horizon/anax/cli/cliconfig"
	"github.com/open-horizon/anax/cli/cliutils"
	"github.com/open-horizon/anax/common"
	"github.com/open-horizon/anax/compcheck"
	"github.com/open-horizon/anax/exchange"
	"github.com/open-horizon/anax/exchangecommon"
	"github.com/open-horizon/anax/externalpolicy"
	_ "github.com/open-horizon/anax/externalpolicy/text_language"
	"github.com/open-horizon/anax/i18n"
	"github.com/open-horizon/anax/persistence"
	"github.com/open-horizon/anax/policy"
	"github.com/open-horizon/anax/semanticversion"
	"os"
)

type ExchangeNodes struct {
	LastIndex int                        `json:"lastIndex"`
	Nodes     map[string]exchange.Device `json:"nodes"`
}

type ContainerStat struct {
	Name    string `json:"name"`
	Image   string `json:"image"`
	Created int    `json:"created"`
	State   string `json:"state"`
}

type ExNodeStatusService struct {
	AgreementId     string          `json:"agreementId"`
	ServiceUrl      string          `json:"serviceUrl"`
	OrgId           string          `json:"orgid"`
	Version         string          `json:"version"`
	Arch            string          `json:"arch"`
	ContainerStatus []ContainerStat `json:"containerStatus"`
	OperatorStatus  interface{}     `json:"operatorStatus,omitempty"`
	ConfigState     string          `json:"configState"`
}

type ExchangeNodeStatus struct {
	Connectivity    map[string]bool       `json:"connectivity,omitempty"`
	Services        []ExNodeStatusService `json:"services"`
	RunningServices string                `json:"runningServices"`
	LastUpdated     string                `json:"lastUpdated,omitempty"`
}

func NodeList(org string, credToUse string, node string, namesOnly bool, exchangeHandler cliutils.ServiceHandler) error {
	cliutils.SetWhetherUsingApiKey(credToUse)
	var nodeOrg string
	var err error
	if nodeOrg, node, err = cliutils.TrimOrg(org, node); err != nil {
		return err
	}
	if node == "*" {
		node = ""
	}
	if namesOnly && node == "" {
		// Only display the names
		var resp ExchangeNodes
		if _, err := exchangeHandler.Get("orgs/"+nodeOrg+"/nodes"+cliutils.AddSlash(node), cliutils.OrgAndCreds(org, credToUse), &resp); err != nil {
			return err
		}
		nodes := []string{}
		for n := range resp.Nodes {
			nodes = append(nodes, n)
		}
		jsonBytes, err := json.MarshalIndent(nodes, "", cliutils.JSON_INDENT)
		if err != nil {
			return cliutils.CLIError{StatusCode: cliutils.JSON_PARSING_ERROR, i18n.GetMessagePrinter().Sprintf("failed to marshal 'exchange node list' output: %v", err))
		}
		fmt.Printf("%s\n", jsonBytes)
	} else {
		// Display the full resources
		var nodes ExchangeNodes
		if httpCode, err := exchangeHandler.Get("orgs/"+nodeOrg+"/nodes"+cliutils.AddSlash(node), cliutils.OrgAndCreds(org, credToUse), &nodes); err != nil {
			return err
		} else if httpCode == 404 && node != "" {
			return cliutils.CLIError{StatusCode: cliutils.NOT_FOUND, i18n.GetMessagePrinter().Sprintf("node '%s' not found in org %s", node, nodeOrg))
		}
		output, err := cliutils.MarshalIndent(nodes.Nodes, "exchange node list")
		if err != nil {
			return err
		}
		fmt.Println(output)
	}

	return nil
}

// Create a node with the given information.
// The function will check if the node exists. If it exists, then only the token will be updated.
// If checkNode is false, it means that the node existance has been check somewhere else, the function will
// assume the node does not exist.
func NodeCreate(org, nodeIdTok, node, token, userPw, arch string, nodeName string, nodeType string, checkNode bool, exchangeHandler cliutils.ServiceHandler) error {
	// get message printer
	msgPrinter := i18n.GetMessagePrinter()

	// They should specify either nodeIdTok (for backward compat) or node and token, but not both
	var nodeId, nodeToken string
	if node != "" || token != "" {
		if node == "" || token == "" {
			return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, msgPrinter.Sprintf("if node or token are specified then they both must be specified"))
		}
		// at this point we know both node and token were specified
		if nodeIdTok != "" {
			return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, msgPrinter.Sprintf("do not specify both the -n flag and the node and token positional arguments. They mean the same thing."))
		}
		nodeId = node
		nodeToken = token
	} else {
		// here we know neither node nor token were specified
		if nodeIdTok == "" {
			return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, msgPrinter.Sprintf("either the node and token positional arguments, or the -n flag must be specified."))
		}
		nodeId, nodeToken = cliutils.SplitIdToken(nodeIdTok)
	}

	if nodeName == "" {
		nodeName = nodeId
	}

	cliutils.SetWhetherUsingApiKey(userPw)

	// validate the node type
	if nodeType != "" && nodeType != persistence.DEVICE_TYPE_DEVICE && nodeType != persistence.DEVICE_TYPE_CLUSTER {
		return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, msgPrinter.Sprintf("Wrong node type specified: %v. It must be 'device' or 'cluster'.", nodeType))
	}

	//Check if the node exists or not
	var nodes ExchangeNodes
	nodeExists := false
	if checkNode {
		if httpCode, err := exchangeHandler.Get("orgs/"+org+"/nodes/"+nodeId, cliutils.OrgAndCreds(org, userPw), &nodes); err != nil {
			return err
		} else if httpCode == 401 {
			// Invalid creds means the user doesn't exist, or pw is wrong
			user, _ := cliutils.SplitIdToken(userPw)
			return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, msgPrinter.Sprintf("user '%s' does not exist with the specified password.", user))
		} else if httpCode == 200 {
			nodeExists = true
		}
	}

	var err error
	var httpCode int
	var resp struct {
		Code string `json:"code"`
		Msg  string `json:"msg"`
	}
	if nodeExists {
		msgPrinter.Printf("Node %v exists. Only the node token will be updated.", nodeId)
		msgPrinter.Println()
		if arch != "" || nodeType != "" {
			msgPrinter.Printf("The node arch and node type will be ignored if they are specified.")
			msgPrinter.Println()
		}
		patchNodeReq := NodeExchangePatchToken{Token: nodeToken}
		if httpCode, err = exchangeHandler.Patch("orgs/"+org+"/nodes/"+nodeId, cliutils.OrgAndCreds(org, userPw), patchNodeReq, &resp); err != nil {
			return err
		}
	} else {
		// create the node with given node type
		if nodeType == "" {
			nodeType = persistence.DEVICE_TYPE_DEVICE
		}
		putNodeReq := exchange.PutDeviceRequest{Token: nodeToken, Name: nodeName, NodeType: nodeType, SoftwareVersions: make(map[string]string), PublicKey: []byte(""), Arch: arch}
		if httpCode, err = exchangeHandler.Put("orgs/"+org+"/nodes/"+nodeId+"?"+cliutils.NOHEARTBEAT_PARAM, cliutils.OrgAndCreds(org, userPw), putNodeReq, &resp); err != nil {
			return err
		}
	}

	if httpCode == 401 {
		// Invalid creds means the user doesn't exist, or pw is wrong
		user, _ := cliutils.SplitIdToken(userPw)
		return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, msgPrinter.Sprintf("user '%s' does not exist with the specified password.", user))
	} else if httpCode == 403 {
		// Access denied means either the node exists and is owned by another user or it doesn't exist but user reached the maxNodes threshold.
		var nodesOutput exchange.GetDevicesResponse
		if httpCode, err = exchangeHandler.Get("orgs/"+org+"/nodes/"+nodeId, cliutils.OrgAndCreds(org, userPw), &nodesOutput); err != nil {
			return err
		}
		if httpCode == 200 {
			// Node exists. Figure out who is the owner and tell the user
			var ok bool
			var ourNode exchange.Device
			if ourNode, ok = nodesOutput.Devices[cliutils.OrgAndCreds(org, nodeId)]; !ok {
				return cliutils.CLIError{StatusCode: cliutils.INTERNAL_ERROR, msgPrinter.Sprintf("key '%s' not found in exchange nodes output", cliutils.OrgAndCreds(org, nodeId)))
			}
			return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, msgPrinter.Sprintf("can not update existing node %s because it is owned by another user (%s)", nodeId, ourNode.Owner))
		} else if httpCode == 404 {
			// Node doesn't exist. MaxNodes reached or 403 means real access denied, display the message from the exchange
			if resp.Msg != "" {
				fmt.Println(resp.Msg)
			}
		}
	} else if httpCode == 201 {
		if nodeExists {
			msgPrinter.Printf("Node %v updated.", nodeId)
			msgPrinter.Println()
		} else {
			if resp.Msg != "" {
				fmt.Println(resp.Msg)
			}
			msgPrinter.Printf("Node %v created.", nodeId)
			msgPrinter.Println()
		}
	}

	return nil
}

func NodeUpdate(org string, credToUse string, node string, filePath string, exchangeHandler cliutils.ServiceHandler) error {
	// get message printer
	msgPrinter := i18n.GetMessagePrinter()

	cliutils.SetWhetherUsingApiKey(credToUse)
	var nodeOrg string
	var err error
	if nodeOrg, node, err = cliutils.TrimOrg(org, node); err != nil {
		return err
	}

	//check that the node exists
	var nodeReq ExchangeNodes
	if httpCode, err := exchangeHandler.Get("orgs/"+nodeOrg+"/nodes/"+node, cliutils.OrgAndCreds(org, credToUse), &nodeReq); err != nil {
		return err
	} else if httpCode == 404 {
		return cliutils.CLIError{StatusCode: cliutils.NOT_FOUND, msgPrinter.Sprintf("Node %s/%s not found in the Horizon Exchange.", nodeOrg, node))
	}

	attribute, err := cliconfig.ReadJsonFileWithLocalConfig(filePath)
	if err != nil {
		return err
	}

	findPatchType := make(map[string]interface{})
	if err := json.Unmarshal([]byte(attribute), &findPatchType); err != nil {
		return cliutils.CLIError{StatusCode: cliutils.JSON_PARSING_ERROR, msgPrinter.Sprintf("failed to unmarshal attribute: %v", err))
	}

	// check invalid attributes
	for k, _ := range findPatchType {
		if k != "userInput" && k != "pattern" && k != "heartbeatIntervals" {
			return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, msgPrinter.Sprintf("Cannot update attribute %v. Supported attributes are: userInput, pattern, heartbeatIntervals.", k))
		}
	}

	updated := false
	for k, v := range findPatchType {
		bytes, err := json.Marshal(v)
		if err != nil {
			return cliutils.CLIError{StatusCode: cliutils.JSON_PARSING_ERROR, msgPrinter.Sprintf("failed to marshal attribute input %s: %v", v, err))
		}
		patch := make(map[string]interface{})
		if k == "userInput" {
			ui := []policy.UserInput{}
			if err := json.Unmarshal(bytes, &ui); err != nil {
				return cliutils.CLIError{StatusCode: cliutils.JSON_PARSING_ERROR, msgPrinter.Sprintf("failed to unmarshal attribute input %s: %v", v, err))
			}
			// validate userInput
			// if node has a pattern, check the service is defined in top level services
			nodes := nodeReq.Nodes
			if len(nodes) != 1 {
				return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, msgPrinter.Sprintf("Expecting 1 exchange node, but get %d nodes", len(nodes)))
			}

			var node exchange.Device
			nId := ""
			for id, n := range nodes {
				node = n
				nId = id
				break
			}

			// verify node userinput for pattern case
			verifyNodeUserInput(org, credToUse, node, nId, ui)

			// verify node userinput for policy case
			verifyNodeUserInputsForPolicy(org, credToUse, node, ui)

			patch[k] = ui
		} else if k == "pattern" {
			pattern := ""
			if err := json.Unmarshal(bytes, &pattern); err != nil {
				return cliutils.CLIError{StatusCode: cliutils.JSON_PARSING_ERROR, msgPrinter.Sprintf("failed to unmarshal pattern attribute input %s: %v", v, err))
			} else {
				patch[k] = pattern
			}
		} else if k == "heartbeatIntervals" {
			hb := exchange.HeartbeatIntervals{}
			if err := json.Unmarshal(bytes, &hb); err != nil {
				return cliutils.CLIError{StatusCode: cliutils.JSON_PARSING_ERROR, msgPrinter.Sprintf("failed to unmarshal heartbeat input %s: %v", v, err))
			} else {
				patch[k] = hb
			}
		}

		msgPrinter.Printf("Updating %v for node %v/%v in the Horizon Exchange.", k, nodeOrg, node)
		msgPrinter.Println()
		if _, err := exchangeHandler.Patch("orgs/"+nodeOrg+"/nodes/"+node, cliutils.OrgAndCreds(org, credToUse), patch, nil); err != nil {
			return err
		}
		msgPrinter.Printf("Attribute %v updated.", k)
		msgPrinter.Println()

		updated = true
	}

	// Tell user that the device will re-evaluating the agreements based on the node update, if necessary.
	if updated {
		for _, v := range nodeReq.Nodes {
			var exchNode exchange.Device
			bytes, err := json.Marshal(v)
			if err != nil {
				return cliutils.CLIError{StatusCode: cliutils.JSON_PARSING_ERROR, msgPrinter.Sprintf("failed to marshal attribute input %s: %v", v, err))
			}
			if err := json.Unmarshal(bytes, &exchNode); err != nil {
				return cliutils.CLIError{StatusCode: cliutils.JSON_PARSING_ERROR, msgPrinter.Sprintf("failed to unmarshal exchange node %s: %v", v, err))
			}

			// the exchange node is registered with a device and the update is not heartbeat interval, then give user more info.
			skipReEval := false
			if _, ok := findPatchType["heartbeatIntervals"]; ok && len(findPatchType) == 1 {
				skipReEval = true
			}

			if exchNode.PublicKey != "" && !skipReEval {
				msgPrinter.Printf("Device will re-evaluate all agreements based on the update. Existing agreements might be cancelled and re-negotiated.")
				msgPrinter.Println()
			}
			break
		}
	}

	return nil
}

type NodeExchangePatchName struct {
	Name string `json:"name"`
}

type NodeExchangePatchToken struct {
	Token string `json:"token"`
}

func NodeSetToken(org, credToUse, node, token string, exchangeHandler cliutils.ServiceHandler) error {
	cliutils.SetWhetherUsingApiKey(credToUse)
	var nodeOrg string
	var err error
	if nodeOrg, node, err = cliutils.TrimOrg(org, node); err != nil {
		return err
	}
	patchNodeReq := NodeExchangePatchToken{Token: token}
	if _, err := exchangeHandler.Patch("orgs/"+nodeOrg+"/nodes/"+node, cliutils.OrgAndCreds(org, credToUse), patchNodeReq, nil); err != nil {
		return err
	}
	
	return nil
}

func NodeConfirm(org, node, token string, nodeIdTok string, exchangeHandler cliutils.ServiceHandler) error {
	// get message printer
	msgPrinter := i18n.GetMessagePrinter()

	cliutils.SetWhetherUsingApiKey("")

	// check the input
	if nodeIdTok != "" {
		if node != "" || token != "" {
			return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, msgPrinter.Sprintf("-n is mutually exclusive with <node> and <token> arguments."))
		}
	} else {
		if node == "" && token == "" {
			nodeIdTok = os.Getenv("HZN_EXCHANGE_NODE_AUTH")
		}
	}

	var err error
	if nodeIdTok != "" {
		node, token = cliutils.SplitIdToken(nodeIdTok)
		if node != "" {
			// trim the org off the node id. the HZN_EXCHANGE_NODE_AUTH may contain the org id.
			if _, node, err = cliutils.TrimOrg(org, node); err != nil {
				return err
			}
		}
	}

	if node == "" || token == "" {
		return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, msgPrinter.Sprintf("Please specify both node and token."))
	}

	if httpCode, err := exchangeHandler.Get("orgs/"+org+"/nodes/"+node, cliutils.OrgAndCreds(org, node+":"+token), nil); err != nil {
		return err
	} else if httpCode == 200 {
		msgPrinter.Printf("Node id and token are valid.")
		msgPrinter.Println()
	}
	// else cliutils.ExchangeGet() already gave the error msg

	return nil
}

func NodeRemove(org, credToUse, node string, force bool, exchangeHandler cliutils.ServiceHandler) error {
	// get message printer
	msgPrinter := i18n.GetMessagePrinter()

	cliutils.SetWhetherUsingApiKey(credToUse)
	var nodeOrg string
	var err error
	if nodeOrg, node, err = cliutils.TrimOrg(org, node); err != nil {
		return err
	}

	if !force {
		cliutils.ConfirmRemove(msgPrinter.Sprintf("Are you sure you want to remove node %v/%v from the Horizon Exchange?", nodeOrg, node))
	}

	if httpCode, err := exchangeHandler.Delete("orgs/"+nodeOrg+"/nodes/"+node, cliutils.OrgAndCreds(org, credToUse)); err != nil {
		return err
	} else if httpCode == 404 {
		return cliutils.CLIError{StatusCode: cliutils.NOT_FOUND, msgPrinter.Sprintf("node '%s' not found in org %s", node, nodeOrg))
	}

	return nil
}

func NodeListPolicy(org string, credToUse string, node string, exchangeHandler cliutils.ServiceHandler) error {
	// get message printer
	msgPrinter := i18n.GetMessagePrinter()

	cliutils.SetWhetherUsingApiKey(credToUse)
	var nodeOrg string
	var err error
	if nodeOrg, node, err = cliutils.TrimOrg(org, node); err != nil {
		return err
	}

	// check node exists first
	var nodes ExchangeNodes
	if httpCode, err := exchangeHandler.Get("orgs/"+nodeOrg+"/nodes"+cliutils.AddSlash(node), cliutils.OrgAndCreds(org, credToUse), &nodes); err != nil {
		return err
	} else if httpCode == 404 {
		return cliutils.CLIError{StatusCode: cliutils.NOT_FOUND, msgPrinter.Sprintf("node '%v/%v' not found.", nodeOrg, node))
	}

	// list policy
	var policy exchange.ExchangeNodePolicy
	exchangeHandler.Get("orgs/"+nodeOrg+"/nodes"+cliutils.AddSlash(node)+"/policy", cliutils.OrgAndCreds(org, credToUse), &policy)

	// display
	output, err := cliutils.DisplayAsJson(policy)
	if err != nil {
		return cliutils.CLIError{StatusCode: cliutils.JSON_PARSING_ERROR, i18n.GetMessagePrinter().Sprintf("failed to marshal node policy output: %v", err))
	}

	fmt.Println(output)

	return nil
}

func NodeAddPolicy(org string, credToUse string, node string, jsonFilePath string, exchangeHandler cliutils.ServiceHandler) error {
	// get message printer
	msgPrinter := i18n.GetMessagePrinter()

	cliutils.SetWhetherUsingApiKey(credToUse)
	var nodeOrg string
	var err error
	if nodeOrg, node, err = cliutils.TrimOrg(org, node); err != nil {
		return err
	}

	// Read in the policy metadata
	newBytes, err := cliconfig.ReadJsonFileWithLocalConfig(jsonFilePath)
	if err != nil {
		return err
	}
	var policyFile exchangecommon.NodePolicy
	err = json.Unmarshal(newBytes, &policyFile)
	if err != nil {
		return cliutils.CLIError{StatusCode: cliutils.JSON_PARSING_ERROR, msgPrinter.Sprintf("failed to unmarshal json input file %s: %v", jsonFilePath, err))
	}

	//Check the policy file format
	err = policyFile.ValidateAndNormalize()
	if err != nil {
		return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, msgPrinter.Sprintf("Incorrect policy format in file %s: %v", jsonFilePath, err))
	}

	// let the user aware of the new node policy format.
	if policyFile.IsDeploymentEmpty() {
		msgPrinter.Printf("Note: No properties and constraints are specified under 'deployment' attribute. The top level properties and constraints will be used.")
		msgPrinter.Println()
	}

	// check node exists first
	var nodes ExchangeNodes
	if httpCode, err := exchangeHandler.Get("orgs/"+nodeOrg+"/nodes"+cliutils.AddSlash(node), cliutils.OrgAndCreds(org, credToUse), &nodes); err != nil {
		return err
	} else if httpCode == 404 {
		return cliutils.CLIError{StatusCode: cliutils.NOT_FOUND, msgPrinter.Sprintf("node '%v/%v' not found.", nodeOrg, node))
	}

	// add/replce node policy
	exchNodePol := exchange.ExchangeNodePolicy{NodePolicy: policyFile, NodePolicyVersion: exchangecommon.NODEPOLICY_VERSION_VERSION_2}
	msgPrinter.Printf("Updating Node policy and re-evaluating all agreements based on this policy. Existing agreements might be cancelled and re-negotiated.")
	msgPrinter.Println()
	exchangeHandler.Put("orgs/"+nodeOrg+"/nodes/"+node+"/policy"+"?"+cliutils.NOHEARTBEAT_PARAM, cliutils.OrgAndCreds(org, credToUse), exchNodePol, nil)

	msgPrinter.Printf("Node policy updated.")
	msgPrinter.Println()

	return nil
}

func NodeUpdatePolicy(org, credToUse, node string, jsonfile string, exchangeHandler cliutils.ServiceHandler) error {
	// get message printer
	msgPrinter := i18n.GetMessagePrinter()

	msgPrinter.Printf("Warning: This command is deprecated. It will continue to be supported until the next major release. Please use 'hzn exchange node addpolicy' to update the node policy.")
	msgPrinter.Println()

	cliutils.SetWhetherUsingApiKey(credToUse)
	var nodeOrg string
	var err error
	if nodeOrg, node, err = cliutils.TrimOrg(org, node); err != nil {
		return err
	}

	attribute, err := cliconfig.ReadJsonFileWithLocalConfig(jsonfile)
	if err != nil {
		return err
	}

	//Check if the node policy exists in the exchange
	var newPolicy exchange.ExchangeNodePolicy
	if httpCode, err := exchangeHandler.Get("orgs/"+nodeOrg+"/nodes"+cliutils.AddSlash(node)+"/policy", cliutils.OrgAndCreds(org, credToUse), &newPolicy); err != nil {
		return err
	} else if httpCode == 404 {
		return cliutils.CLIError{StatusCode: cliutils.NOT_FOUND, msgPrinter.Sprintf("Node policy not found for node %s/%s", nodeOrg, node))
	}

	findAttrType := make(map[string]interface{})
	err = json.Unmarshal([]byte(attribute), &findAttrType)
	if err != nil {
		return cliutils.CLIError{StatusCode: cliutils.JSON_PARSING_ERROR, msgPrinter.Sprintf("failed to unmarshal attribute input %s: %v", attribute, err))
	}

	attribName := ""
	if _, ok := findAttrType["properties"]; ok {
		attribName = "properties"
		propertiesPatch := make(map[string]externalpolicy.PropertyList)
		err := json.Unmarshal([]byte(attribute), &propertiesPatch)
		if err != nil {
			return cliutils.CLIError{StatusCode: cliutils.JSON_PARSING_ERROR, msgPrinter.Sprintf("failed to unmarshal attribute input %s for %s: %v", attribute, attribName, err))
		}
		newProp := propertiesPatch["properties"]
		err = newProp.Validate()
		if err != nil {
			return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, msgPrinter.Sprintf("Invalid property list %s: %v", newProp, err))
		}
		newPolicy.Properties = newProp
	} else if _, ok = findAttrType["constraints"]; ok {
		attribName = "constraints"
		constraintPatch := make(map[string]externalpolicy.ConstraintExpression)
		err := json.Unmarshal([]byte(attribute), &constraintPatch)
		if err != nil {
			return cliutils.CLIError{StatusCode: cliutils.JSON_PARSING_ERROR, msgPrinter.Sprintf("failed to unmarshal attribute input %s for %ss: %v", attribute, attribName, err))
		}
		newConstr := constraintPatch["constraints"]
		_, err = newConstr.Validate()
		if err != nil {
			return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, msgPrinter.Sprintf("Invalid constraint expression %s: %v", newConstr, err))
		}
		newPolicy.Constraints = newConstr
	} else if _, ok = findAttrType["deployment"]; ok {
		attribName = "deployment"
		externpolPatch := make(map[string]externalpolicy.ExternalPolicy)
		err := json.Unmarshal([]byte(attribute), &externpolPatch)
		if err != nil {
			return cliutils.CLIError{StatusCode: cliutils.JSON_PARSING_ERROR, msgPrinter.Sprintf("failed to unmarshal attribute input %s for %s: %v", attribute, attribName, err))
		}
		externPol := externpolPatch["deployment"]
		err = (&externPol).ValidateAndNormalize()
		if err != nil {
			return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, msgPrinter.Sprintf("Invalid deployment attribute %s: %v", externPol, err))
		}
		newPolicy.Deployment = externPol
	} else if _, ok = findAttrType["management"]; ok {
		attribName = "management"
		externpolPatch := make(map[string]externalpolicy.ExternalPolicy)
		err := json.Unmarshal([]byte(attribute), &externpolPatch)
		if err != nil {
			return cliutils.CLIError{StatusCode: cliutils.JSON_PARSING_ERROR, msgPrinter.Sprintf("failed to unmarshal attribute input %s for %s: %v", attribute, attribName, err))
		}
		externPol := externpolPatch["management"]
		err = (&externPol).ValidateAndNormalize()
		if err != nil {
			return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, msgPrinter.Sprintf("Invalid management attribute %s: %v", externPol, err))
		}
		newPolicy.Management = externPol
	} else {
		return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, msgPrinter.Sprintf("Failed to find valid attribute to update in input %s. Valid attribute names are properties, constraints, deployment and management.", attribute))
	}

	msgPrinter.Printf("Updating Node policy %v attribute for node %v in the horizon exchange and re-evaluating all agreements based on this policy. Existing agreements might be cancelled and re-negotiated.", attribName, node)
	msgPrinter.Println()
	exchNodePol := exchange.ExchangeNodePolicy{NodePolicy: newPolicy.NodePolicy, NodePolicyVersion: exchangecommon.NODEPOLICY_VERSION_VERSION_2}
	exchangeHandler.Put("orgs/"+nodeOrg+"/nodes/"+node+"/policy"+"?"+cliutils.NOHEARTBEAT_PARAM, cliutils.OrgAndCreds(org, credToUse), exchNodePol, nil)
	msgPrinter.Printf("Node policy %v attribute updated for node %v in the horizon exchange.", attribName, node)
	msgPrinter.Println()

	return nil
}

func NodeRemovePolicy(org, credToUse, node string, force bool, exchangeHandler cliutils.ServiceHandler) error {
	// get message printer
	msgPrinter := i18n.GetMessagePrinter()

	cliutils.SetWhetherUsingApiKey(credToUse)
	var nodeOrg string
	var err error
	if nodeOrg, node, err = cliutils.TrimOrg(org, node); err != nil {
		return err
	}
	if !force {
		cliutils.ConfirmRemove(msgPrinter.Sprintf("Are you sure you want to remove node policy for %v/%v from the Horizon Exchange?", nodeOrg, node))
	}

	// check node exists first
	var nodes ExchangeNodes
	if httpCode, err := exchangeHandler.Get("orgs/"+nodeOrg+"/nodes"+cliutils.AddSlash(node), cliutils.OrgAndCreds(org, credToUse), &nodes); err != nil {
		return err
	} else if httpCode == 404 {
		return cliutils.CLIError{StatusCode: cliutils.NOT_FOUND, msgPrinter.Sprintf("node '%v/%v' not found.", nodeOrg, node))
	}

	// remove policy
	msgPrinter.Printf("Removing Node policy and re-evaluating all agreements. Existing agreements might be cancelled and re-negotiated.")
	msgPrinter.Println()
	exchangeHandler.Delete("orgs/"+nodeOrg+"/nodes/"+node+"/policy", cliutils.OrgAndCreds(org, credToUse))
	msgPrinter.Printf("Node policy removed.")
	msgPrinter.Println()

	return nil
}

// Format for outputting eventlog objects
type EventLog struct {
	Id         string           `json:"record_id"` // unique primary key for records
	Timestamp  string           `json:"timestamp"` // converted to "yyyy-mm-dd hh:mm:ss" format
	Severity   string           `json:"severity"`  // info, warning or error
	Message    string           `json:"message"`
	EventCode  string           `json:"event_code"`
	SourceType string           `json:"source_type"`  // the type of the source. It can be agreement, service, image, workload etc.
	Source     *json.RawMessage `json:"event_source"` // source involved for this event.
}

// NodeListErrors Displays the node errors currently surfaced to the exchange
func NodeListErrors(org string, credToUse string, node string, long bool, exchangeHandler cliutils.ServiceHandler) error {
	msgPrinter := i18n.GetMessagePrinter()

	cliutils.SetWhetherUsingApiKey(credToUse)
	var nodeOrg string
	var err error
	if nodeOrg, node, err = cliutils.TrimOrg(org, node); err != nil {
		return err
	}

	// Check that the node specified exists in the exchange
	var nodes ExchangeNodes
	if httpCode, err := exchangeHandler.Get("orgs/"+nodeOrg+"/nodes"+cliutils.AddSlash(node), cliutils.OrgAndCreds(org, credToUse), &nodes); err != nil {
		return err
	} else if httpCode == 404 {
		return cliutils.CLIError{StatusCode: cliutils.NOT_FOUND, msgPrinter.Sprintf("node '%v/%v' not found.", nodeOrg, node))
	}

	var resp exchange.ExchangeSurfaceError
	if _, err = exchangeHandler.Get("orgs/"+nodeOrg+"/nodes/"+node+"/errors", cliutils.OrgAndCreds(org, credToUse), &resp); err != nil {
		return err
	}

	errorList := []persistence.SurfaceError{}
	if resp.ErrorList != nil {
		errorList = resp.ErrorList
	}

	if !long {
		jsonBytes, err := json.MarshalIndent(errorList, "", cliutils.JSON_INDENT)
		if err != nil {
			return cliutils.CLIError{StatusCode: cliutils.JSON_PARSING_ERROR, msgPrinter.Sprintf("failed to marshal 'hzn exchange node listerrors' output: %v", err))
		}
		fmt.Printf("%s\n", jsonBytes)
	} else {
		long_output := make([]EventLog, len(errorList))
		for i, v := range errorList {
			var fullVSlice []persistence.EventLogRaw
			cliutils.HorizonGet(fmt.Sprintf("eventlog/all?record_id=%s", v.Record_id), []int{200}, &fullVSlice, false)
			if len(fullVSlice) == 0 {
				return cliutils.CLIError{StatusCode: cliutils.JSON_PARSING_ERROR, i18n.GetMessagePrinter().Sprintf("Error: event record could not be found"))
			}
			fullV := fullVSlice[0]
			long_output[i].Id = fullV.Id
			long_output[i].Timestamp = cliutils.ConvertTime(fullV.Timestamp)
			long_output[i].Severity = fullV.Severity
			long_output[i].Message = fullV.Message
			long_output[i].EventCode = fullV.EventCode
			long_output[i].SourceType = fullV.SourceType
			long_output[i].Source = fullV.Source
		}
		jsonBytes, err := json.MarshalIndent(long_output, "", cliutils.JSON_INDENT)
		if err != nil {
			return cliutils.CLIError{StatusCode: cliutils.JSON_PARSING_ERROR, i18n.GetMessagePrinter().Sprintf("failed to marshal 'hzn exchange node listerrors' output: %v", err))
		}
		fmt.Printf("%s\n", jsonBytes)
	}

	return nil
}

// NodeListStatus list the node run time status, for example service container status.
func NodeListStatus(org string, credToUse string, node string, exchangeHandler cliutils.ServiceHandler) error {
	msgPrinter := i18n.GetMessagePrinter()

	cliutils.SetWhetherUsingApiKey(credToUse)
	var nodeOrg string
	var err error
	if nodeOrg, node, err = cliutils.TrimOrg(org, node); err != nil {
		return err
	}

	var nodeStatus ExchangeNodeStatus
	if httpCode, err := exchangeHandler.Get("orgs/"+nodeOrg+"/nodes"+cliutils.AddSlash(node)+"/status", cliutils.OrgAndCreds(org, credToUse), &nodeStatus); err != nil {
		return err
	} else if httpCode == 404 {
		return cliutils.CLIError{StatusCode: cliutils.NOT_FOUND, msgPrinter.Sprintf("node status not found for node '%v/%v'.", nodeOrg, node))
	}

	output, err := cliutils.MarshalIndent(nodeStatus, "exchange node liststatus")
	if err != nil {
		return err
	}
	fmt.Println(output)

	return nil
}

// Verify the node user input for the pattern case. Make sure that the given
// user input are compatible with the pattern.
func verifyNodeUserInput(org string, credToUse string, node exchange.Device, nId string, ui []policy.UserInput) error {
	msgPrinter := i18n.GetMessagePrinter()

	if node.Pattern == "" {
		return nil
	}

	msgPrinter.Printf("Verifying userInputs with the node pattern %v.", node.Pattern)
	msgPrinter.Println()

	// get exchange context
	ec, err := cliutils.GetUserExchangeContext(org, credToUse)
	if err != nil {
		return err
	}

	// compcheck.UserInputCompatible function calls the exchange package that calls glog.
	// set the glog stderrthreshold to 3 (fatal) in order for glog error messages not showing up in the output
	flag.Set("stderrthreshold", "3")
	flag.Parse()

	uiCheckInput := compcheck.UserInputCheck{}
	uiCheckInput.NodeArch = node.Arch
	uiCheckInput.PatternId = node.Pattern
	uiCheckInput.NodeId = nId
	uiCheckInput.NodeUserInput = ui

	// now we can call the real code to check if the policies are compatible.
	// the policy validation are done wthin the calling function.
	compOutput, err := compcheck.UserInputCompatible(ec, &uiCheckInput, true, msgPrinter)
	if err != nil {
		return cliutils.CLIError{StatusCode: cliutils.CLI_GENERAL_ERROR, err.Error())
	} else if !compOutput.Compatible {
		msgPrinter.Printf("Error varifying the given user input with the node pattern %v:", node.Pattern)
		msgPrinter.Println()
		if compOutput.Reason != nil {
			for id, reason := range compOutput.Reason {
				if reason != msgPrinter.Sprintf("Compatible") {
					fmt.Printf("  %v: %v\n", id, reason)
				}
			}
		}
		return cliutils.CLIError{StatusCode: cliutils.CLI_GENERAL_ERROR, msgPrinter.Sprintf("Unable to update the node because of the above error."))
	}

	return nil
}

// Verify the node user input for the policy case. Make sure that the given
// user input are compatible with the service in exchange
func verifyNodeUserInputsForPolicy(org string, credToUse string, node exchange.Device, ui []policy.UserInput) error {
	msgPrinter := i18n.GetMessagePrinter()
	msgPrinter.Printf("Verifying userInputs for node using policy.")
	msgPrinter.Println()

	if len(ui) != 0 {
		top_services := []common.AbstractServiceFile{}
		dep_services := map[string]exchange.ServiceDefinition{}
		for _, u := range ui {
			uInput := u

			serviceOrg := uInput.ServiceOrgid
			serviceUrl := uInput.ServiceUrl
			serviceVersionRange := uInput.ServiceVersionRange
			serviceArch := uInput.ServiceArch

			if &uInput.ServiceVersionRange == nil || uInput.ServiceVersionRange == "" {
				serviceVersionRange = "0.0.0"
			}

			msgPrinter.Printf("Start validating userinput %v, %v, %v, %v", serviceOrg, serviceUrl, serviceVersionRange, serviceArch)
			msgPrinter.Println()

			var vExp *semanticversion.Version_Expression
			var err error
			if vExp, err = semanticversion.Version_Expression_Factory(serviceVersionRange); err != nil {
				return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, msgPrinter.Sprintf("Unable to validate exchange node userInput, error: %v", "", err))
			}
			versionRange := vExp.Get_expression()

			if &uInput.ServiceArch == nil || uInput.ServiceArch == "" {
				serviceArch = node.Arch
			}

			// get exchange context
			ec, err := cliutils.GetUserExchangeContext(org, credToUse)
			if err != nil {
				return err
			}

			serviceDefResolverHandler := exchange.GetHTTPServiceDefResolverHandler(ec)
			var bpUserInput []policy.UserInput

			svcSpec := compcheck.NewServiceSpec(serviceUrl, serviceOrg, versionRange, serviceArch)
			if validated, message, sTop, _, sDeps, err := compcheck.VerifyUserInputForService(svcSpec, serviceDefResolverHandler, bpUserInput, ui, node.GetNodeType(), msgPrinter); !validated {
				if err != nil && message != "" {
					return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, msgPrinter.Sprintf("Unable to validate exchange node userInput, message: %v, error: %v", message, err))
				} else if err != nil {
					return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, msgPrinter.Sprintf("Unable to validate exchange node userInput, error: %v", err))
				} else {
					return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, msgPrinter.Sprintf("Unable to validate exchange node userInput, message: %v", message))
				}
			} else {
				top_services = append(top_services, sTop)
				for id, s := range sDeps {
					dep_services[id] = s
				}

				// check service type and node type compatibility
				if compatible_t, reason_t := compcheck.CheckTypeCompatibility(node.NodeType, sTop, msgPrinter); compatible_t != true {
					return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, msgPrinter.Sprintf("Unable to validate exchange node userInput: %v", reason_t))
				}
			}

		}

		// check redundant userinput for service
		if err := compcheck.CheckRedundantUserinput(top_services, dep_services, ui, msgPrinter); err != nil {
			cliutils.Warning(msgPrinter.Sprintf("validate exchange node/userinput %v ", err))
		}
	}

	return nil
}
