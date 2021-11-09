package policy

import (
	"encoding/json"
	"fmt"
	"github.com/open-horizon/anax/cli/cliconfig"
	"github.com/open-horizon/anax/cli/cliutils"
	"github.com/open-horizon/anax/exchangecommon"
	"github.com/open-horizon/anax/externalpolicy"
	"github.com/open-horizon/anax/i18n"
	"net/http"
)

func List() error {
	// Get the node policy info
	nodePolicy := exchangecommon.NodePolicy{}
	cliutils.HorizonGet("node/policy", []int{200}, &nodePolicy, false)

	// Output the combined info
	output, err := cliutils.DisplayAsJson(nodePolicy)
	if err != nil {
		return cliutils.CLIError{StatusCode: cliutils.JSON_PARSING_ERROR, i18n.GetMessagePrinter().Sprintf("failed to marshal 'hzn policy list' output: %v", err))
	}

	fmt.Println(output)

	return nil
}

func Update(fileName string) error {
	msgPrinter := i18n.GetMessagePrinter()

	ep := new(exchangecommon.NodePolicy)
	readInputFile(fileName, ep)

	// let the user aware of the new node policy format.
	if ep.IsDeploymentEmpty() {
		msgPrinter.Printf("Note: No properties and constraints are specified under 'deployment' attribute. The top level properties and constraints will be used.")
		msgPrinter.Println()
	}

	readOnlyBuiltIns := externalpolicy.ListReadOnlyProperties()
	includedBuiltIns := ""
	for _, builtInProp := range readOnlyBuiltIns {
		if ep.Properties.HasProperty(builtInProp) {
			if includedBuiltIns == "" {
				includedBuiltIns = builtInProp
			} else {
				includedBuiltIns = fmt.Sprintf("%s, %s", includedBuiltIns, builtInProp)
			}
		}
	}
	if includedBuiltIns != "" {
		msgPrinter.Printf("Warning: built-in properties %v are read-only. The given value will be ignored.", includedBuiltIns)
		msgPrinter.Println()
	}

	cliutils.HorizonPutPost(http.MethodPost, "node/policy", []int{201, 200}, ep, true)

	msgPrinter.Printf("Updating Horizon node policy and re-evaluating all agreements based on this node policy. Existing agreements might be cancelled and re-negotiated.")
	msgPrinter.Println()

	return nil
}

func Patch(patch string) error {
	msgPrinter := i18n.GetMessagePrinter()
	msgPrinter.Printf("Warning: This command is deprecated. It will continue to be supported until the next major release. Please use 'hzn policy update' to update the node policy.")
	msgPrinter.Println()

	cliutils.HorizonPutPost(http.MethodPatch, "node/policy", []int{201, 200}, patch, true)

	msgPrinter.Printf("Horizon node policy updated.")
	msgPrinter.Println()

	return nil
}

func readInputFile(filePath string, inputFileStruct *exchangecommon.NodePolicy) error {
	newBytes, err := cliconfig.ReadJsonFileWithLocalConfig(filePath)
	if err != nil {
		return err
	}
	err = json.Unmarshal(newBytes, inputFileStruct)
	if err != nil {
		return cliutils.CLIError{StatusCode: cliutils.JSON_PARSING_ERROR, i18n.GetMessagePrinter().Sprintf("failed to unmarshal json input file %s: %v", filePath, err))
	}

	return nil
}

func Remove(force bool) error {
	if !force {
		cliutils.ConfirmRemove(i18n.GetMessagePrinter().Sprintf("Are you sure you want to remove the node policy?"))
	}

	msgPrinter := i18n.GetMessagePrinter()
	if _, err := cliutils.HorizonDelete("node/policy", []int{200, 204}, []int{}, false); err != nil {
		return err
	}

	msgPrinter.Printf("Removing Horizon node policy and re-evaluating all agreements. Existing agreements might be cancelled and re-negotiated.")
	msgPrinter.Println()

	return nil
}

// Display an empty policy template as an object.
func New() error {
	// get message printer
	msgPrinter := i18n.GetMessagePrinter()

	var policy_template = []string{
		`{`,
		`  "properties": [      /* ` + msgPrinter.Sprintf("A list of policy properties that describe the object.") + ` */`,
		`                       /* ` + msgPrinter.Sprintf("It applies to both deployment and node management.") + `*/`,
		`                       /* ` + msgPrinter.Sprintf("It usually containts the built-in node properties.") + `*/`,
		`    {`,
		`       "name": "",`,
		`       "value": null`,
		`    }`,
		`  ],`,
		`  "constraints": [     /* ` + msgPrinter.Sprintf("A list of constraint expressions of the form <property name> <operator> <property value>,") + ` */`,
		`                       /* ` + msgPrinter.Sprintf("separated by boolean operators AND (&&) or OR (||).") + `*/`,
		`                       /* ` + msgPrinter.Sprintf("It applies to both deployment and node management.") + `*/`,
		`                       /* ` + msgPrinter.Sprintf("It should be empty unless deployment and managment have the same constraint expressions.") + `*/`,
		`       "" `,
		`  ], `,
		`  "deployment": {      /* ` + msgPrinter.Sprintf("Policies that are used for deployment only.") + ` */`,
		`      "properties": [  /* ` + msgPrinter.Sprintf("A list of policy properties for deployment.") + ` */`,
		`                       /* ` + msgPrinter.Sprintf("It overwrites the properties with the same name on the top level.") + `*/`,
		`        {`,
		`           "name": "",`,
		`           "value": null`,
		`        }`,
		`      ],`,
		`      "constraints": [ /* ` + msgPrinter.Sprintf("A list of constraints for deployment.") + ` */`,
		`                       /* ` + msgPrinter.Sprintf("It overwrites all the constraints on the top level if not empty.") + `*/`,
		`         "" `,
		`      ] `,
		`  },`,
		`  "management": {      /* ` + msgPrinter.Sprintf("Policies that are used for node management only.") + ` */`,
		`      "properties": [  /* ` + msgPrinter.Sprintf("A list of policy properties for node management.") + ` */`,
		`                       /* ` + msgPrinter.Sprintf("It overwrites the properties with the same name on the top level.") + `*/`,
		`        {`,
		`           "name": "",`,
		`           "value": null`,
		`        }`,
		`      ],`,
		`      "constraints": [ /* ` + msgPrinter.Sprintf("A list of constraints for node management.") + ` */`,
		`                       /* ` + msgPrinter.Sprintf("It overwrites all the constraints on the top level if not empty.") + `*/`,
		`         "" `,
		`      ] `,
		`  }`,
		`}`,
	}

	for _, s := range policy_template {
		fmt.Println(s)
	}

	return nil
}
