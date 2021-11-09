package exchange

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/open-horizon/anax/cli/cliconfig"
	"github.com/open-horizon/anax/cli/cliutils"
	"github.com/open-horizon/anax/cli/plugin_registry"
	"github.com/open-horizon/anax/cli/policy"
	"github.com/open-horizon/anax/common"
	"github.com/open-horizon/anax/cutil"
	"github.com/open-horizon/anax/exchange"
	"github.com/open-horizon/anax/exchangecommon"
	"github.com/open-horizon/anax/externalpolicy"
	_ "github.com/open-horizon/anax/externalpolicy/text_language"
	"github.com/open-horizon/anax/i18n"
	"github.com/open-horizon/anax/persistence"
	"github.com/open-horizon/rsapss-tool/verify"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type ServiceDockAuthExch struct {
	Registry string `json:"registry"`
	UserName string `json:"username"`
	Token    string `json:"token"`
}

// List the the service resources for the given org.
// The userPw can be the userId:password auth or the nodeId:token auth.
func ServiceList(credOrg, userPw, service string, namesOnly bool, filePath string, exSvcOpYamlForce bool, exchangeHandler cliutils.ServiceHandler) error {
	// get message printer
	msgPrinter := i18n.GetMessagePrinter()

	cliutils.SetWhetherUsingApiKey(userPw)
	var svcOrg string
	var err error
	if svcOrg, service, err = cliutils.TrimOrg(credOrg, service); err != nil {
		return err
	}
	if service == "*" {
		service = ""
	}

	if service == "" && filePath != "" {
		return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, msgPrinter.Sprintf("-f can only be used when one service is specified."))
	}

	if exSvcOpYamlForce && filePath == "" {
		return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, msgPrinter.Sprintf("-F can only be used when -f is specified."))
	}

	if namesOnly && service == "" {
		// Only display the names
		var resp exchange.GetServicesResponse
		if _, err := exchangeHandler.Get("orgs/"+svcOrg+"/services"+cliutils.AddSlash(service), cliutils.OrgAndCreds(credOrg, userPw), &resp); err != nil {
			return err
		}
		services := []string{}

		for k := range resp.Services {
			services = append(services, k)
		}
		jsonBytes, err := json.MarshalIndent(services, "", cliutils.JSON_INDENT)
		if err != nil {
			return cliutils.CLIError{StatusCode: cliutils.JSON_PARSING_ERROR, msgPrinter.Sprintf("failed to marshal 'hzn exchange service list' output: %v", err))
		}
		fmt.Printf("%s\n", jsonBytes)
	} else {
		// Display the full resources
		var services exchange.GetServicesResponse

		if httpCode, err := exchangeHandler.Get("orgs/"+svcOrg+"/services"+cliutils.AddSlash(service), cliutils.OrgAndCreds(credOrg, userPw), &services); err != nil {
			return nil
		} else if httpCode == 404 && service != "" {
			return cliutils.CLIError{StatusCode: cliutils.NOT_FOUND, msgPrinter.Sprintf("service '%s' not found in org %s", service, svcOrg))
		}

		exchServices := services.Services
		var clusterDeployment string
		var svcId string
		for sId, s := range exchServices {
			// when only one service is specified, save the ClusterDeployment and service id for later use
			if service != "" {
				clusterDeployment = s.ClusterDeployment
				svcId = sId
			}

			// only display 100 charactors for ClusterDeployment because it is usually very long
			if s.ClusterDeployment != "" && len(s.ClusterDeployment) > 100 {
				if service != "" && !namesOnly {
					// if user specify a service name and -l is specified, then display all of ClusterDeployment
					// this will give user a way to examine all of it.
					continue
				}
				s_copy := exchange.ServiceDefinition(s)
				s_copy.ClusterDeployment = s.ClusterDeployment[0:100] + "..."
				exchServices[sId] = s_copy
			}
		}
		jsonBytes, err := json.MarshalIndent(exchServices, "", cliutils.JSON_INDENT)
		if err != nil {
			return cliutils.CLIError{StatusCode: cliutils.JSON_PARSING_ERROR, msgPrinter.Sprintf("failed to marshal 'hzn exchange service list' output: %v", err))
		}
		fmt.Println(string(jsonBytes))

		// save the kube operator yaml archive to file if filePath is specified and one service is specified
		if filePath != "" {
			if clusterDeployment == "" {
				msgPrinter.Printf("Ignoring -f because the clusterDeployment attribute is empty for this service.")
				msgPrinter.Println()
			} else {
				SaveOpYamlToFile(svcId, clusterDeployment, filePath, exSvcOpYamlForce)
			}
		}
	}

	return nil
}

// ServicePublish signs the MS def and puts it in the exchange
func ServicePublish(org, userPw, jsonFilePath, keyFilePath, pubKeyFilePath string, dontTouchImage bool, pullImage bool, registryTokens []string, overwrite bool, servicePolicyFilePath string, public string, exchangeHandler cliutils.ServiceHandler) error {
	// get message printer
	msgPrinter := i18n.GetMessagePrinter()

	if pubKeyFilePath != "" && keyFilePath == "" {
		return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, msgPrinter.Sprintf("Flag -K cannot be specified without -k flag."))
	}
	if dontTouchImage && pullImage {
		return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, msgPrinter.Sprintf("Flags -I and -P are mutually exclusive."))
	}
	cliutils.SetWhetherUsingApiKey(userPw)

	// Read in the service metadata
	newBytes, err := cliconfig.ReadJsonFileWithLocalConfig(jsonFilePath)
	if err != nil {
		return err
	}
	var svcFile common.ServiceFile
	err = json.Unmarshal(newBytes, &svcFile)
	if err != nil {
		return cliutils.CLIError{StatusCode: cliutils.JSON_PARSING_ERROR, msgPrinter.Sprintf("failed to unmarshal json input file %s: %v", jsonFilePath, err))
	}
	if svcFile.Org != "" && svcFile.Org != org {
		return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, msgPrinter.Sprintf("the org specified in the input file (%s) must match the org specified on the command line (%s)", svcFile.Org, org))
	}
	if public != "" {
		public = strings.ToLower(public)
		if public != "true" && public != "false" {
			return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, msgPrinter.Sprintf("Need to set 'true' or 'false' when specifying flag --public."))
		} else {
			// Override public key with key set in the hzn command
			svcFile.Public, err = strconv.ParseBool(public)
			if err != nil {
				return cliutils.CLIError{StatusCode: cliutils.INTERNAL_ERROR, msgPrinter.Sprintf("failed to parse %s: %v", public, err))
			}

		}
	}

	// Compensate for old service definition files
	svcFile.SupportVersionRange()

	// validate the service attributes
	ec, err := cliutils.GetUserExchangeContext(org, userPw)
	if err != nil {
		return nil
	}
	if err := common.ValidateService(exchange.GetHTTPServiceDefResolverHandler(ec), &svcFile, msgPrinter); err != nil {
		return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, msgPrinter.Sprintf("Error validating the input service: %v", err))
	}

	if err := SignAndPublish(&svcFile, org, userPw, jsonFilePath, keyFilePath, pubKeyFilePath, dontTouchImage, pullImage, registryTokens, !overwrite, exchangeHandler); err != nil {
		return err
	}

	// create service policy if servicePolicyFilePath is defined
	if servicePolicyFilePath != "" {
		serviceAddPolicyService := fmt.Sprintf("%s/%s_%s_%s", svcFile.Org, svcFile.URL, svcFile.Version, svcFile.Arch) //svcFile.URL + "_" + svcFile.Version + "_" +
		msgPrinter.Printf("Adding service policy for service: %v", serviceAddPolicyService)
		msgPrinter.Println()
		if err := ServiceAddPolicy(org, userPw, serviceAddPolicyService, servicePolicyFilePath, exchangeHandler); err != nil {
			return err
		}
		msgPrinter.Printf("Service policy added for service: %v", serviceAddPolicyService)
		msgPrinter.Println()
	}

	return nil
}

// Sign and publish the service definition. This is a function that is reusable across different hzn commands.
func SignAndPublish(sf *common.ServiceFile, org, userPw, jsonFilePath, keyFilePath, pubKeyFilePath string, dontTouchImage bool, pullImage bool, registryTokens []string, promptForOverwrite bool, exchangeHandler cliutils.ServiceHandler) error {
	// get message printer
	msgPrinter := i18n.GetMessagePrinter()

	svcInput := exchange.ServiceDefinition{Label: sf.Label, Description: sf.Description, Public: sf.Public, Documentation: sf.Documentation, URL: sf.URL, Version: sf.Version, Arch: sf.Arch, Sharable: sf.Sharable, MatchHardware: sf.MatchHardware, RequiredServices: sf.RequiredServices, UserInputs: sf.UserInputs}

	baseDir := filepath.Dir(jsonFilePath)
	var usedPubKeyBytes []byte
	var usedPubKeyBytes_cluster []byte
	var err error
	usedPubKeyName := ""
	usedPubKeyName_cluster := ""
	if svcInput.Deployment, svcInput.DeploymentSignature, usedPubKeyBytes, usedPubKeyName, err = SignDeployment(sf.Deployment, sf.DeploymentSignature, baseDir, false, keyFilePath, pubKeyFilePath, dontTouchImage, pullImage); err != nil {
		return err
	}
	if svcInput.ClusterDeployment, svcInput.ClusterDeploymentSignature, usedPubKeyBytes_cluster, usedPubKeyName_cluster, err = SignDeployment(sf.ClusterDeployment, sf.ClusterDeploymentSignature, baseDir, true, keyFilePath, pubKeyFilePath, dontTouchImage, pullImage); err != nil {
		return err
	}

	// Create or update resource in the exchange
	exchId := cutil.FormExchangeIdForService(svcInput.URL, svcInput.Version, svcInput.Arch)
	var output string
	if httpCode, err := exchangeHandler.Get("orgs/"+org+"/services/"+exchId, cliutils.OrgAndCreds(org, userPw), &output); err != nil {
		return err
	} else if httpCode == 200 {
		// check if the service exists with the same version, ask user if -O is not specified.
		if promptForOverwrite {
			cliutils.ConfirmRemove(msgPrinter.Sprintf("Service %v/%v exists in the Exchange, do you want to overwrite it?", org, exchId))
		}
		// Service exists, update it
		msgPrinter.Printf("Updating %s in the Exchange...", exchId)
		msgPrinter.Println()
		if _, err := exchangeHandler.Put("orgs/"+org+"/services/"+exchId, cliutils.OrgAndCreds(org, userPw), svcInput, nil); err != nil {
			return err
		}
	} else {
		// Service not there, create it
		msgPrinter.Printf("Creating %s in the Exchange...", exchId)
		msgPrinter.Println()
		if _, err := exchangeHandler.Post("orgs/"+org+"/services", cliutils.OrgAndCreds(org, userPw), svcInput, nil); err != nil {
			return err
		}
	}

	// Store the public key in the exchange
	var pubKeyNameToStore string
	var pubKeyToStore []byte
	if usedPubKeyName != "" {
		pubKeyNameToStore = usedPubKeyName
		pubKeyToStore = usedPubKeyBytes
	} else if usedPubKeyName_cluster != "" {
		pubKeyNameToStore = usedPubKeyName_cluster
		pubKeyToStore = usedPubKeyBytes_cluster
	}
	if pubKeyNameToStore != "" {
		msgPrinter.Printf("Storing %s with the service in the Exchange...", pubKeyNameToStore)
		msgPrinter.Println()
		if _, err := exchangeHandler.Put("orgs/"+org+"/services/"+exchId+"/keys/"+pubKeyNameToStore, cliutils.OrgAndCreds(org, userPw), pubKeyToStore, nil); err != nil {
			return err
		}
	}

	// Store registry auth tokens in the exchange, if they gave us some
	for _, regTok := range registryTokens {
		parts := strings.SplitN(regTok, ":", 3)
		regstry := ""
		username := ""
		token := ""
		if len(parts) == 3 {
			regstry = parts[0]
			username = parts[1]
			token = parts[2]
		}

		if parts[0] == "" || len(parts) < 3 || parts[2] == "" {
			msgPrinter.Printf("Error: registry-token value of '%s' is not in the required format: registry:user:token. Not storing that in the Horizon exchange.", regTok)
			msgPrinter.Println()
			continue
		}
		msgPrinter.Printf("Storing %s with the service in the Exchange...", regTok)
		msgPrinter.Println()
		regTokExch := ServiceDockAuthExch{Registry: regstry, UserName: username, Token: token}
		if _, err := exchangeHandler.Post("orgs/"+org+"/services/"+exchId+"/dockauths", cliutils.OrgAndCreds(org, userPw), regTokExch, nil); err != nil {
			return err
		}
	}

	// If necessary, tell the user to push the container images to the docker registry. Get the list of images they need to manually push
	// from the appropriate deployment config plugin.
	//
	// We will NOT tell the user to manually push images if the publish command has already pushed the images. By default, the act
	// of publishing a service will also cause the docker images used by the service to be pushed to a docker repo. The dontTouchImage flag tells
	// the publish command to skip pushing the images.
	if dontTouchImage {
		imageMap := map[string]bool{}

		if sf.Deployment != nil && sf.Deployment != "" {
			if images, err := plugin_registry.DeploymentConfigPlugins.GetContainerImages(sf.Deployment); err != nil {
				return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, msgPrinter.Sprintf("unable to get container images from deployment configuration: %v", err))
			} else if images != nil {
				for _, img := range images {
					imageMap[img] = true
				}
			}
		}

		if len(imageMap) > 0 {
			msgPrinter.Printf("If you haven't already, push your docker images to the registry:")
			msgPrinter.Println()
			for image, _ := range imageMap {
				fmt.Printf("  docker push %s\n", image)
			}
		}
	}

	return nil
}

// The function signs the given deployment if it is not empty abd not already signed. It returns the deployment, its signature
// and the public key whose matching private was used for signing the deployment.
func SignDeployment(deployment interface{}, deploymentSignature string, baseDir string, isCluster bool, keyFilePath string, pubKeyFilePath string, dontTouchImage bool, pullImage bool) (string, string, []byte, string, error) {
	// get message printer
	msgPrinter := i18n.GetMessagePrinter()

	// tags for related filed name in the service, for proper output messages
	tag_d := "deployment"
	tag_dsig := "deploymentSignature"
	if isCluster {
		tag_d = "clusterDeployment"
		tag_dsig = "clusterDeploymentSignature"
	}

	// The deployment field can be json object (map), string (for pre-signed), or nil
	var newDeployment, newDeploymentSignature, newPubKeyName string
	var newPubKeyToStore []byte
	var newPrivKeyToStore *rsa.PrivateKey
	var err error
	switch dep := deployment.(type) {
	case nil:
		deployment = ""
		if deploymentSignature != "" {
			cliutils.Warning(msgPrinter.Sprintf("the '%v' field is non-blank, but being ignored, because the '%v' field is null", tag_dsig, tag_d))
		}
		newDeploymentSignature = ""

	case map[string]interface{}:
		// We know we need to sign the deployment config, so make sure a real key file was provided.
		if newPrivKeyToStore, newPubKeyToStore, newPubKeyName, err = cliutils.GetSigningKeys(keyFilePath, pubKeyFilePath); err != nil {
			return "", "", nil, "", err
		}

		// Construct and sign the deployment string.
		msgPrinter.Printf("Signing service...")
		msgPrinter.Println()

		// Setup the Plugin context with variables that might be needed by 1 or more of the plugins.
		ctx := plugin_registry.NewPluginContext()
		ctx.Add("currentDir", baseDir)
		ctx.Add("dontTouchImage", dontTouchImage)
		ctx.Add("pullImage", pullImage)

		// Allow the right plugin to sign the deployment configuration.
		depStr, sig, err := plugin_registry.DeploymentConfigPlugins.SignByOne(dep, newPrivKeyToStore, ctx)
		if err != nil {
			return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, msgPrinter.Sprintf("unable to sign deployment config: %v", err))
		}

		newDeployment = depStr
		newDeploymentSignature = sig

	case string:
		// Means this service is pre-signed
		if deployment != "" && deploymentSignature == "" {
			return cliutils.CLIError{StatusCode: cliutils.JSON_PARSING_ERROR, msgPrinter.Sprintf("the '%v' field is a non-empty string, which implies this service is pre-signed, but the '%v' field is empty", tag_d, tag_dsig))
		}
		newDeployment = dep
		newDeploymentSignature = deploymentSignature

	default:
		return cliutils.CLIError{StatusCode: cliutils.JSON_PARSING_ERROR, msgPrinter.Sprintf("'%v' field is invalid type. It must be either a json object or a string (for pre-signed)", tag_d))
	}

	return newDeployment, newDeploymentSignature, newPubKeyToStore, newPubKeyName, nil
}

// ServiceVerify verifies the deployment strings of the specified service resource in the exchange.
// The userPw can be the userId:password auth or the nodeId:token auth.
func ServiceVerify(org, userPw, service, keyFilePath string, exchangeHandler cliutils.ServiceHandler) error {
	// get message printer
	msgPrinter := i18n.GetMessagePrinter()

	cliutils.SetWhetherUsingApiKey(userPw)
	var svcorg string
	var err error
	if svcorg, service, err = cliutils.TrimOrg(org, service); err != nil {
		return err
	}
	// Get service resource from exchange
	var output exchange.GetServicesResponse
	if httpCode, err := exchangeHandler.Get("orgs/"+svcorg+"/services/"+service, cliutils.OrgAndCreds(org, userPw), &output); err != nil {
		return err
	} else if httpCode == 404 {
		return cliutils.CLIError{StatusCode: cliutils.NOT_FOUND, msgPrinter.Sprintf("service '%s' not found in org %s", service, svcorg))
	}

	// Loop thru services array, checking the deployment string signature
	svc, ok := output.Services[svcorg+"/"+service]
	if !ok {
		return cliutils.CLIError{StatusCode: cliutils.INTERNAL_ERROR, msgPrinter.Sprintf("key '%s' not found in resources returned from exchange", svcorg+"/"+service))
	}
	someInvalid := false

	//take default key if empty, make sure the key exists
	if keyFilePath, err = cliutils.VerifySigningKeyInput(keyFilePath, true); err != nil {
		return err
	}

	// verify the deployment
	if svc.Deployment != "" {
		verified, err := verify.Input(keyFilePath, svc.DeploymentSignature, []byte(svc.Deployment))
		if err != nil {
			return cliutils.CLIError{StatusCode: cliutils.CLI_GENERAL_ERROR, msgPrinter.Sprintf("error verifying deployment string with %s: %v", keyFilePath, err))
		} else if !verified {
			msgPrinter.Printf("Deployment string was not signed with the private key associated with this public key %v.", keyFilePath)
			msgPrinter.Println()
			someInvalid = true
		}
	}
	// verify the cluster deployment
	if svc.ClusterDeployment != "" {
		verified, err := verify.Input(keyFilePath, svc.ClusterDeploymentSignature, []byte(svc.ClusterDeployment))
		if err != nil {
			return cliutils.CLIError{StatusCode: cliutils.CLI_GENERAL_ERROR, msgPrinter.Sprintf("error verifying cluster deployment string with %s: %v", keyFilePath, err))
		} else if !verified {
			msgPrinter.Printf("Cluster deployment string was not signed with the private key associated with this public key %v.", keyFilePath)
			msgPrinter.Println()
			someInvalid = true
		}
	}
	// else if they all turned out to be valid, we will tell them that at the end

	if someInvalid {
		os.Exit(cliutils.SIGNATURE_INVALID)
	} else {
		msgPrinter.Printf("All signatures verified")
		msgPrinter.Println()
	}

	return nil
}

func ServiceRemove(org, userPw, service string, force bool, exchangeHandler cliutils.ServiceHandler) error {
	// get message printer
	msgPrinter := i18n.GetMessagePrinter()

	cliutils.SetWhetherUsingApiKey(userPw)
	var svcorg string
	var err error
	if svcorg, service, err = cliutils.TrimOrg(org, service); err != nil {
		return err
	}
	if !force {
		cliutils.ConfirmRemove(msgPrinter.Sprintf("Are you sure you want to remove service %v/%v from the Horizon Exchange?", svcorg, service))
	}

	if httpCode, err := exchangeHandler.Delete("orgs/"+svcorg+"/services/"+service, cliutils.OrgAndCreds(org, userPw)); err != nil {
		return err
	} else if httpCode == 404 {
		return cliutils.CLIError{StatusCode: cliutils.NOT_FOUND, msgPrinter.Sprintf("service '%s' not found in org %s", service, svcorg))
	}

	return nil
}

// List the public keys for a service that can be used to verify the deployment signature for the service
// The userPw can be the userId:password auth or the nodeId:token auth.
func ServiceListKey(org, userPw, service, keyName string, exchangeHandler cliutils.ServiceHandler) error {
	// get message printer
	msgPrinter := i18n.GetMessagePrinter()

	cliutils.SetWhetherUsingApiKey(userPw)
	var svcorg string
	var err error
	if svcorg, service, err = cliutils.TrimOrg(org, service); err != nil {
		return err
	}
	if keyName == "" {
		// Only display the names
		var output string
		if httpCode, err := exchangeHandler.Get("orgs/"+svcorg+"/services/"+service+"/keys", cliutils.OrgAndCreds(org, userPw), &output); err != nil {
			return err
		} else if httpCode == 404 {
			return cliutils.CLIError{StatusCode: cliutils.NOT_FOUND, msgPrinter.Sprintf("keys not found"))
		}
		fmt.Printf("%s\n", output)
	} else {
		// Display the content of the key
		var output []byte
		if httpCode, err := exchangeHandler.Get("orgs/"+svcorg+"/services/"+service+"/keys/"+keyName, cliutils.OrgAndCreds(org, userPw), &output); err != nil {
			return err
		} else if httpCode == 404 {
			return cliutils.CLIError{StatusCode: cliutils.NOT_FOUND, msgPrinter.Sprintf("key '%s' not found", keyName))
		}
		fmt.Printf("%s", string(output))
	}

	return nil
}

func ServiceRemoveKey(org, userPw, service, keyName string, exchangeHandler cliutils.ServiceHandler) error {
	// get message printer
	msgPrinter := i18n.GetMessagePrinter()

	cliutils.SetWhetherUsingApiKey(userPw)
	var svcorg string
	var err error
	if svcorg, service, err = cliutils.TrimOrg(org, service); err != nil {
		return err
	}
	if httpCode, err := exchangeHandler.Delete("orgs/"+svcorg+"/services/"+service+"/keys/"+keyName, cliutils.OrgAndCreds(org, userPw)); err != nil {
		return err
	} else if httpCode == 404 {
		return cliutils.CLIError{StatusCode: cliutils.NOT_FOUND, msgPrinter.Sprintf("key '%s' not found", keyName))
	}

	return nil
}

// List the docker auth that can be used to get the images for the service
// The userPw can be the userId:password auth or the nodeId:token auth.
func ServiceListAuth(org, userPw, service string, authId uint, exchangeHandler cliutils.ServiceHandler) error {
	// get message printer
	msgPrinter := i18n.GetMessagePrinter()

	cliutils.SetWhetherUsingApiKey(userPw)
	var svcorg string
	var err error
	if svcorg, service, err = cliutils.TrimOrg(org, service); err != nil {
		return err
	}
	var authIdStr string
	if authId != 0 {
		authIdStr = "/" + strconv.Itoa(int(authId))
	}
	var output string
	if httpCode, err := exchangeHandler.Get("orgs/"+svcorg+"/services/"+service+"/dockauths"+authIdStr, cliutils.OrgAndCreds(org, userPw), &output); err != nil {
		return err
	} else if httpCode == 404 {
		if authId != 0 {
			return cliutils.CLIError{StatusCode: cliutils.NOT_FOUND, msgPrinter.Sprintf("docker auth %d not found", authId))
		} else {
			return cliutils.CLIError{StatusCode: cliutils.NOT_FOUND, msgPrinter.Sprintf("docker auths not found"))
		}
	}
	fmt.Printf("%s\n", output)

	return nil
}

func ServiceRemoveAuth(org, userPw, service string, authId uint, exchangeHandler cliutils.ServiceHandler) error {
	// get message printer
	msgPrinter := i18n.GetMessagePrinter()

	cliutils.SetWhetherUsingApiKey(userPw)
	var svcorg string
	var err error
	if svcorg, service, err = cliutils.TrimOrg(org, service); err != nil {
		return err
	}
	authIdStr := strconv.Itoa(int(authId))
	if httpCode, err := exchangeHandler.Delete("orgs/"+svcorg+"/services/"+service+"/dockauths/"+authIdStr, cliutils.OrgAndCreds(org, userPw)); err != nil {
		return err
	} else if httpCode == 404 {
		return cliutils.CLIError{StatusCode: cliutils.NOT_FOUND, msgPrinter.Sprintf("docker auth %d not found", authId))
	}

	return nil
}

//ServiceListPolicy lists the policy for the service in the Horizon Exchange
func ServiceListPolicy(org string, credToUse string, service string, exchangeHandler cliutils.ServiceHandler) error {
	// get message printer
	msgPrinter := i18n.GetMessagePrinter()

	cliutils.SetWhetherUsingApiKey(credToUse)
	var svcorg string
	var err error
	if svcorg, service, err = cliutils.TrimOrg(org, service); err != nil {
		return err
	}

	// Check that the service exists
	var services exchange.ServiceDefinition
	if httpCode, err := exchangeHandler.Get("orgs/"+svcorg+"/services"+cliutils.AddSlash(service), cliutils.OrgAndCreds(org, credToUse), &services); err != nil {
		return err
	} else if httpCode == 404 {
		return cliutils.CLIError{StatusCode: cliutils.NOT_FOUND, msgPrinter.Sprintf("service '%v/%v' not found.", svcorg, service))
	}
	var policy exchange.ExchangeServicePolicy
	if _, err := exchangeHandler.Get("orgs/"+svcorg+"/services"+cliutils.AddSlash(service)+"/policy", cliutils.OrgAndCreds(org, credToUse), &policy); err != nil {
		return err
	}

	buf := new(bytes.Buffer)
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", cliutils.JSON_INDENT)
	err = enc.Encode(policy.ServicePolicy)
	if err != nil {
		return cliutils.CLIError{StatusCode: cliutils.JSON_PARSING_ERROR, msgPrinter.Sprintf("failed to marshal 'hzn exchange service listpolicy' output: %v", err))
	}
	fmt.Println(string(buf.String()))

	return nil
}

//ServiceAddPolicy adds a policy or replaces an existing policy for the service in the Horizon Exchange
func ServiceAddPolicy(org string, credToUse string, service string, jsonFilePath string, exchangeHandler cliutils.ServiceHandler) error {
	// get message printer
	msgPrinter := i18n.GetMessagePrinter()

	cliutils.SetWhetherUsingApiKey(credToUse)
	var svcorg string
	var err error
	if svcorg, service, err = cliutils.TrimOrg(org, service); err != nil {
		return err
	}
	fullServiceName := fmt.Sprintf(svcorg + "/" + service)

	// Read in the policy metadata
	newBytes, err := cliconfig.ReadJsonFileWithLocalConfig(jsonFilePath)
	if err != nil {
		return err
	}
	var policyFile exchangecommon.ServicePolicy
	err = json.Unmarshal(newBytes, &policyFile)
	if err != nil {
		return cliutils.CLIError{StatusCode: cliutils.JSON_PARSING_ERROR, msgPrinter.Sprintf("failed to unmarshal json input file %s: %v", jsonFilePath, err))
	}

	//Check the policy file format
	err = policyFile.GetExternalPolicy().ValidateAndNormalize()
	if err != nil {
		return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, msgPrinter.Sprintf("Incorrect policy format in file %s: %v", jsonFilePath, err))
	}

	// Check that the service exists
	var services exchange.GetServicesResponse
	if httpCode, err := exchangeHandler.Get("orgs/"+svcorg+"/services"+cliutils.AddSlash(service), cliutils.OrgAndCreds(org, credToUse), &services); err != nil {
		return err
	} else if httpCode == 404 {
		return cliutils.CLIError{StatusCode: cliutils.NOT_FOUND, msgPrinter.Sprintf("service '%v/%v' not found.", svcorg, service))
	}
	serviceFromExchange := services.Services[fullServiceName]

	serviceName := serviceFromExchange.URL
	serviceVersion := serviceFromExchange.Version
	serviceArch := serviceFromExchange.Arch

	// Set default built in properties before publishing to the exchange
	msgPrinter.Printf("Adding built-in property values...")
	msgPrinter.Println()
	msgPrinter.Printf("The following property value will be overriden: service.url, service.name, service.org, service.version, service.arch")
	msgPrinter.Println()

	properties := policyFile.Properties
	properties.Add_Property(externalpolicy.Property_Factory(externalpolicy.PROP_SVC_URL, serviceName), true)
	properties.Add_Property(externalpolicy.Property_Factory(externalpolicy.PROP_SVC_NAME, serviceName), true)
	properties.Add_Property(externalpolicy.Property_Factory(externalpolicy.PROP_SVC_ORG, svcorg), true)
	properties.Add_Property(externalpolicy.Property_Factory(externalpolicy.PROP_SVC_VERSION, serviceVersion), true)
	properties.Add_Property(externalpolicy.Property_Factory(externalpolicy.PROP_SVC_ARCH, serviceArch), true)

	policyFile.Properties = properties

	//Check the policy file format again
	err = policyFile.ValidateAndNormalize()
	if err != nil {
		return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, msgPrinter.Sprintf("Incorrect policy format in file %s: %v", jsonFilePath, err))
	}

	// add/replace service policy
	msgPrinter.Printf("Updating Service policy  and re-evaluating all agreements based on this Service policy. Existing agreements might be cancelled and re-negotiated.")
	msgPrinter.Println()
	if _, err := exchangeHandler.Put("orgs/"+svcorg+"/services/"+service+"/policy", cliutils.OrgAndCreds(org, credToUse), policyFile, nil); err != nil {
		return err
	}

	msgPrinter.Printf("Service policy updated.")
	msgPrinter.Println()

	return nil
}

//ServiceRemovePolicy removes the service policy in the exchange
func ServiceRemovePolicy(org string, credToUse string, service string, force bool, exchangeHandler cliutils.ServiceHandler) error {
	// get message printer
	msgPrinter := i18n.GetMessagePrinter()

	cliutils.SetWhetherUsingApiKey(credToUse)
	var svcorg string
	var err error
	if svcorg, service, err = cliutils.TrimOrg(org, service); err != nil {
		return err
	}

	//confirm removal with user
	if !force {
		cliutils.ConfirmRemove(msgPrinter.Sprintf("Are you sure you want to remove service policy for %v/%v from the Horizon Exchange?", svcorg, service))
	}

	// Check that the service exists
	var services exchange.ServiceDefinition
	if httpCode, err := exchangeHandler.Get("orgs/"+svcorg+"/services"+cliutils.AddSlash(service), cliutils.OrgAndCreds(org, credToUse), &services); err != nil {
		return err
	} else if httpCode == 404 {
		return cliutils.CLIError{StatusCode: cliutils.NOT_FOUND, msgPrinter.Sprintf("service '%v/%v' not found.", svcorg, service))
	}

	//remove service policy
	msgPrinter.Printf("Removing Service policy and re-evaluating all agreements. Existing agreements might be cancelled and re-negotiated.")
	msgPrinter.Println()
	if _, err := exchangeHandler.Delete("orgs/"+svcorg+"/services/"+service+"/policy", cliutils.OrgAndCreds(org, credToUse)); err != nil {
		return err
	}
	msgPrinter.Printf("Service policy removed.")
	msgPrinter.Println()

	return nil
}

// Display an empty service policy template as an object.
func ServiceNewPolicy() error {
	return policy.New()
}

// Get the Kubernetes operator yaml archive from the cluster deployment string and save it to a file
func SaveOpYamlToFile(sId string, clusterDeployment string, filePath string, forceOverwrite bool) error {
	// get message printer
	msgPrinter := i18n.GetMessagePrinter()

	archiveData := GetOpYamlArchiveFromClusterDepl(clusterDeployment)

	fileName := filePath
	if info, err := os.Stat(filePath); err == nil && info.IsDir() {
		_, id, err := cliutils.TrimOrg("", sId) // remove the org part
		if err != nil {
			return err
		}
		fileName = filepath.Join(filePath, id+"_operator_yaml.tar.gz")
	}

	if _, err := os.Stat(fileName); err == nil {
		if !forceOverwrite {
			cliutils.ConfirmRemove(msgPrinter.Sprintf("File %v already exists, do you want to overwrite?", fileName))
		}
	}

	file, err := os.Create(fileName)
	if err != nil {
		return cliutils.CLIError{StatusCode: cliutils.INTERNAL_ERROR, msgPrinter.Sprintf("Failed to create file %v. %v", fileName, err))
	}
	defer file.Close()

	if _, err := file.Write(archiveData); err != nil {
		return cliutils.CLIError{StatusCode: cliutils.INTERNAL_ERROR, msgPrinter.Sprintf("Failed to save the clusterDeployment operator yaml to file %v. %v", fileName, err))
	}

	msgPrinter.Printf("The clusterDeployment operator yaml archive is saved to file %v", fileName)
	msgPrinter.Println()

	return nil
}

// This function getst the operator yaml archive (in .tat.gz format) from the clusterDeployment
// string from a service
func GetOpYamlArchiveFromClusterDepl(deploymentConfig string) []byte {
	// get message printer
	msgPrinter := i18n.GetMessagePrinter()

	// for non cluster type service, return nil
	if deploymentConfig == "" {
		return nil
	}

	if kd, err := persistence.GetKubeDeployment(deploymentConfig); err != nil {
		return cliutils.CLIError{StatusCode: cliutils.JSON_PARSING_ERROR, msgPrinter.Sprintf("error getting kube deployment configuration: %v", err))
	} else {
		archiveData, err := base64.StdEncoding.DecodeString(kd.OperatorYamlArchive)
		if err != nil {
			return cliutils.CLIError{StatusCode: cliutils.JSON_PARSING_ERROR, msgPrinter.Sprintf("error decoding the cluster deployment configuration: %v", err))
		}
		return archiveData
	}

	return nil
}

type ServiceNode struct {
	OrgId          string `json:"orgid"`
	ServiceUrl     string `json:"serviceURL"`
	ServiceVersion string `json:"serviceVersion"`
	ServiceArch    string `json:"serviceArch"`
}

// List the nodes that a service is running on.
func ListServiceNodes(org, userPw, svcId, nodeOrg string, exchangeHandler cliutils.ServiceHandler) error {
	// get message printer
	msgPrinter := i18n.GetMessagePrinter()

	// if nodeOrg is not specified, default to service org
	if nodeOrg == "" {
		nodeOrg = org
	}

	// extract service id
	var svcOrg string
	var err error
	if svcOrg, svcId, err = cliutils.TrimOrg(org, svcId); err != nil {
		return err
	}

	// get service from the Exchange
	var services exchange.GetServicesResponse
	if httpCode, err := exchangeHandler.Get("orgs/"+svcOrg+"/services"+cliutils.AddSlash(svcId), cliutils.OrgAndCreds(org, userPw), &services); err != nil {
		return err
	} else if httpCode == 404 {
		return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, msgPrinter.Sprintf("service id does not exist in the Exchange: %v/%v", svcOrg, svcId))
	} else {
		// extract org id, service url, version, and arch from Exchange
		var svcNode ServiceNode
		for id, _ := range services.Services {
			svcNode = ServiceNode{OrgId: svcOrg, ServiceUrl: services.Services[id].URL, ServiceVersion: services.Services[id].Version, ServiceArch: services.Services[id].Arch}
			break
		}

		// structure we are writing to
		var listNodes map[string]interface{}
		if _, err := exchangeHandler.Post("orgs/"+nodeOrg+"/search/nodes/service", cliutils.OrgAndCreds(org, userPw), svcNode, &listNodes); err != nil {
			return err
		}

		// print list
		if nodes, ok := listNodes["nodes"]; !ok {
			fmt.Println("[]")
		} else {
			jsonBytes, err := json.MarshalIndent(nodes, "", cliutils.JSON_INDENT)
			if err != nil {
				return cliutils.CLIError{StatusCode: cliutils.JSON_PARSING_ERROR, msgPrinter.Sprintf("failed to marshal 'hzn exchange service listnode' output: %v", err))
			}
			fmt.Printf("%s\n", jsonBytes)
		}
	}

	return nil
}
