package attribute

import (
	"encoding/json"
	"fmt"
	"github.com/open-horizon/anax/api"
	"github.com/open-horizon/anax/cli/cliutils"
	"github.com/open-horizon/anax/i18n"
	"github.com/open-horizon/anax/persistence"
)

const HTTPSBasicAuthAttributes = "HTTPSBasicAuthAttributes"

// Our form of the attributes output
type OurAttributes struct {
	Type         string                   `json:"type"`
	Label        string                   `json:"label"`
	ServiceSpecs persistence.ServiceSpecs `json:"service_specs,omitempty"`
	Variables    map[string]interface{}   `json:"variables"`
}

func List() error {
	// Get the attributes
	apiOutput := map[string][]api.Attribute{}
	httpCode, err := cliutils.HorizonGet("attribute", []int{200, cliutils.ANAX_NOT_CONFIGURED_YET}, &apiOutput, false)
	if httpCode == cliutils.ANAX_NOT_CONFIGURED_YET {
		return cliutils.CLIError{StatusCode: cliutils.HTTP_ERROR, Message: i18n.GetMessagePrinter().Sprintf(cliutils.MUST_REGISTER_FIRST)}
	} else if err != nil {
		return err
	}
	var ok bool
	if _, ok = apiOutput["attributes"]; !ok {
		return cliutils.CLIError{StatusCode: cliutils.HTTP_ERROR, Message: i18n.GetMessagePrinter().Sprintf("horizon api attributes output did not include 'attributes' key")}
	}
	apiAttrs := apiOutput["attributes"]

	// Only include interesting fields in our output
	attrs := []OurAttributes{}
	for _, a := range apiAttrs {
		if a.ServiceSpecs == nil {
			attrs = append(attrs, OurAttributes{Type: *a.Type, Label: *a.Label, Variables: *a.Mappings})
		} else {
			attrs = append(attrs, OurAttributes{Type: *a.Type, Label: *a.Label, ServiceSpecs: *a.ServiceSpecs, Variables: *a.Mappings})
		}
	}

	// Convert to json and output
	jsonBytes, err := json.MarshalIndent(attrs, "", cliutils.JSON_INDENT)
	if err != nil {
		return cliutils.CLIError{StatusCode: cliutils.JSON_PARSING_ERROR, Message: i18n.GetMessagePrinter().Sprintf("failed to marshal 'hzn attribute list' output: %v", err)}
	}
	fmt.Printf("%s\n", jsonBytes)

	return nil
}
