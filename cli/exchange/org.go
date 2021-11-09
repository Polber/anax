package exchange

import (
	"encoding/json"
	"fmt"
	"github.com/open-horizon/anax/cli/cliutils"
	"github.com/open-horizon/anax/exchange"
	"github.com/open-horizon/anax/i18n"
	"github.com/open-horizon/edge-sync-service/common"
	"strings"
)

type ExchangeOrgs struct {
	Orgs      map[string]interface{} `json:"orgs"`
	LastIndex int                    `json:"lastIndex"`
}

// use this structure instead of exchange.Organization for updating the org tags
// so that an empty map can be passed into the exchange api without get lost by json.Mashal()
type PatchOrgTags struct {
	Tags map[string]string `json:"tags"`
}

func OrgList(org, userPwCreds, theOrg string, long bool, exchangeHandler cliutils.ServiceHandler) error {
	// get message printer
	msgPrinter := i18n.GetMessagePrinter()

	// if org name is empty, list name of all orgs
	var orgurl string
	nameOnly := false
	if theOrg == "" {
		orgurl = "orgs"
		nameOnly = true
	} else {
		orgurl = "orgs/" + theOrg
	}

	// get orgs
	var orgs ExchangeOrgs
	if httpCode, err := exchangeHandler.Get(orgurl, cliutils.OrgAndCreds(org, userPwCreds), &orgs); err != nil {
		return err
	} else if httpCode == 404 {
		return cliutils.CLIError{StatusCode: cliutils.NOT_FOUND, msgPrinter.Sprintf("org '%s' not found.", theOrg))
	}

	// Print only the names if listing all orgs AND -l was not inputted
	// in the case of -l being true, print all details regardless
	if !long && nameOnly {
		organizations := []string{}
		for o := range orgs.Orgs {
			organizations = append(organizations, o)
		}

		jsonBytes, err := json.MarshalIndent(organizations, "", cliutils.JSON_INDENT)
		if err != nil {
			return cliutils.CLIError{StatusCode: cliutils.JSON_PARSING_ERROR, msgPrinter.Sprintf("failed to marshal 'exchange org list' output: %v", err))
		}
		fmt.Printf("%s\n", jsonBytes)
	} else {
		output, err := cliutils.MarshalIndent(orgs.Orgs, "exchange orgs list")
		if err != nil {
			return err
		}
		fmt.Println(output)
	}

	return nil
}

func OrgCreate(org, userPwCreds, theOrg string, label string, desc string, tags []string, min int, max int, adjust int, maxNodes int, agbot string, exchangeHandler cliutils.ServiceHandler, mmsHandler cliutils.ServiceHandler) error {
	// get message printer
	msgPrinter := i18n.GetMessagePrinter()

	// get credentials
	cliutils.SetWhetherUsingApiKey(userPwCreds)

	// check if the agbot specified by -a exist or not
	if err := CheckAgbot(org, userPwCreds, agbot, exchangeHandler); err != nil {
		return err
	}

	// check constraints on min, max, amnd adjust
	// if any negative values for heartbeat, throw error
	negFlags := []string{}
	if min < 0 {
		negFlags = append(negFlags, "--heartbeatmin")
	}
	if max < 0 {
		negFlags = append(negFlags, "--heartbeatmax")
	}
	if adjust < 0 {
		negFlags = append(negFlags, "--heartbeatadjust")
	}

	// indicate which flags are negative
	if len(negFlags) > 0 {
		negatives := strings.Join(negFlags, ",")
		return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, msgPrinter.Sprintf("Invalid input for %v. Negative integer is not allowed.", negatives))
	}

	// if min is not less than or equal to max, throw error
	if min != 0 && max != 0 && min > max {
		return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, msgPrinter.Sprintf("The value for --heartbeatmin must be less than or equal to the value for --heartbeatmax."))
	}

	if label == "" {
		label = theOrg
	}

	// handle tags. the input is -t mytag1=myvalue1 -t mytag2=mytag2
	orgTags := convertTags(tags, false)

	// validate maxNodes
	if maxNodes < 0 {
		return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, msgPrinter.Sprintf("Invalid input for --max-nodes. Negative integer is not allowed."))
	}

	// add org to exchange
	orgHb := exchange.HeartbeatIntervals{MinInterval: min, MaxInterval: max, IntervalAdjustment: adjust}
	limits := exchange.OrgLimits{MaxNodes: maxNodes}
	postOrgReq := exchange.Organization{Label: label, Description: desc, HeartbeatIntv: &orgHb, Tags: orgTags, Limits: &limits}
	if _, err := exchangeHandler.Post("orgs/"+theOrg, cliutils.OrgAndCreds(org, userPwCreds), postOrgReq, nil); err != nil {
		return err
	}

	msgPrinter.Printf("Organization %v is successfully added to the Exchange.", theOrg)
	msgPrinter.Println()

	// adding the org to the agbot's served list
	if agbot == "" {
		// if -a is not specified, it go get the first agbot it can find
		ag, err := GetDefaultAgbot(org, userPwCreds, exchangeHandler)
		if err != nil {
			return err
		}
		if ag == "" {
			msgPrinter.Printf("No agbot found in the Exchange.")
			msgPrinter.Println()
			return nil

		}
		agbot = ag
	}
	if err := AddOrgToAgbotServingList(org, userPwCreds, theOrg, agbot, exchangeHandler); err != nil {
		return err
	}
	msgPrinter.Printf("Agbot %v is responsible for deploying services in org %v", agbot, theOrg)
	msgPrinter.Println()

	// add org to sync service
	mmsCreateOrgReq := common.Organization{OrgID: theOrg}
	if _, err := mmsHandler.Put("api/v1/organizations/"+theOrg, cliutils.OrgAndCreds(org, userPwCreds), mmsCreateOrgReq, nil); err != nil {
		return err
	}

	msgPrinter.Printf("Organization %v is successfully added to MMS.", theOrg)
	msgPrinter.Println()

	return nil
}

func OrgUpdate(org, userPwCreds, theOrg string, label string, desc string, tags []string, min int, max int, adjust int, maxNodes int, exchangeHandler cliutils.ServiceHandler) error {
	// get message printer
	msgPrinter := i18n.GetMessagePrinter()

	// check existance and also get current attribute values for comparizon later
	var orgs exchange.GetOrganizationResponse
	if httpCode, err := exchangeHandler.Get("orgs/"+theOrg, cliutils.OrgAndCreds(org, userPwCreds), &orgs); err != nil {
		return err
	} else if httpCode == 404 {
		return cliutils.CLIError{StatusCode: cliutils.NOT_FOUND, msgPrinter.Sprintf("org '%s' not found.", theOrg))
	}

	// if --label is specified, update it
	if label != "" {
		newOrgLabel := exchange.Organization{Label: label}
		if _, err := exchangeHandler.Patch("orgs/"+theOrg, cliutils.OrgAndCreds(org, userPwCreds), newOrgLabel, nil); err != nil {
			return err
		}
	}

	// if --description is specified, update it
	if desc != "" {
		newOrgDesc := exchange.Organization{Description: desc}
		if _, err := exchangeHandler.Patch("orgs/"+theOrg, cliutils.OrgAndCreds(org, userPwCreds), newOrgDesc, nil); err != nil {
			return err
		}
	}

	// convert the input tags into map[string]string
	orgTags := convertTags(tags, true)
	if orgTags != nil {
		newTags := PatchOrgTags{Tags: orgTags}
		if _, err := exchangeHandler.Patch("orgs/"+theOrg, cliutils.OrgAndCreds(org, userPwCreds), newTags, nil); err != nil {
			return err
		}
	}

	// do nothing if they are -1
	if min != -1 || max != -1 || adjust != -1 {
		newMin, newMax, newAdjust := getNewHeartbeatAttributes(min, max, adjust, orgs.Orgs[theOrg].HeartbeatIntv)
		orgHb := exchange.HeartbeatIntervals{MinInterval: newMin, MaxInterval: newMax, IntervalAdjustment: newAdjust}
		newOrgHeartbeaat := exchange.Organization{HeartbeatIntv: &orgHb}
		if _, err := exchangeHandler.Patch("orgs/"+theOrg, cliutils.OrgAndCreds(org, userPwCreds), newOrgHeartbeaat, nil); err != nil {
			return err
		}
	}

	// do nothing if maxNodes is -1
	if maxNodes < -1 {
		return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, msgPrinter.Sprintf("Invalid input for --max-nodes. Only -1, 0 and positive integers are allowed."))
	} else if maxNodes > -1 {
		limits := exchange.OrgLimits{MaxNodes: maxNodes}
		newOrgLimits := exchange.Organization{Limits: &limits}
		if _, err := exchangeHandler.Patch("orgs/"+theOrg, cliutils.OrgAndCreds(org, userPwCreds), newOrgLimits, nil); err != nil {
			return err
		}
	}

	msgPrinter.Printf("Organization %v is successfully updated.", theOrg)
	msgPrinter.Println()

	return nil
}

func OrgDel(org, userPwCreds, theOrg, agbot string, force bool, exchangeHandler cliutils.ServiceHandler, mmsHandler cliutils.ServiceHandler) error {
	// get message printer
	msgPrinter := i18n.GetMessagePrinter()

	// Search exchange for org, throw error if not found.
	if httpCode, err := exchangeHandler.Get("orgs/"+theOrg, cliutils.OrgAndCreds(org, userPwCreds), nil); err != nil {
		return err
	} else if httpCode == 404 {
		return cliutils.CLIError{StatusCode: cliutils.NOT_FOUND, msgPrinter.Sprintf("org '%s' not found.", theOrg))
	}

	// check if the agbot specified by -a exist or not
	if err := CheckAgbot(org, userPwCreds, agbot, exchangeHandler); err != nil {
		return err
	}

	// "Are you sure?" prompt
	cliutils.SetWhetherUsingApiKey(userPwCreds)
	if !force {
		cliutils.ConfirmRemove(msgPrinter.Sprintf("Warning: this will also delete all Exchange resources owned by this org (nodes, services, patterns, etc). Are you sure you want to remove org %v from the Horizon Exchange and the MMS?", theOrg))
	}

	if agbot == "" {
		// if -a is not specified, it go get the first agbot it can find
		ag, err := GetDefaultAgbot(org, userPwCreds, exchangeHandler)
		if err != nil {
			return err
		}
		if ag == "" {
			msgPrinter.Printf("No agbot found in the Exchange.")
			msgPrinter.Println()
		} else {
			agbot = ag
			cliutils.Verbose(msgPrinter.Sprintf("Using agbot %v", agbot))
		}
	}

	if agbot != "" {
		var agbotOrg string
		var err error
		if agbotOrg, agbot, err = cliutils.TrimOrg(org, agbot); err != nil {
			return err
		}

		// Load and remove all agbot served patterns associated with this org
		var patternsResp ExchangeAgbotPatterns
		if _, err := exchangeHandler.Get("orgs/"+agbotOrg+"/agbots/"+agbot+"/patterns", cliutils.OrgAndCreds(org, userPwCreds), &patternsResp); err != nil {
			return err
		}

		for patternId, p := range patternsResp.Patterns {
			// Convert pattern's value into JSON and unmarshal it
			var servedPattern ServedPattern
			patternJson, err := cliutils.MarshalIndent(p, "Cannot convert pattern to JSON")
			if err != nil {
				return err
			}
			cliutils.Unmarshal([]byte(patternJson), &servedPattern, msgPrinter.Sprintf("Cannot unmarshal served pattern"))

			if servedPattern.PatternOrg == theOrg || servedPattern.NodeOrg == theOrg {
				cliutils.Verbose(msgPrinter.Sprintf("Removing pattern %s from agbot %s", patternId, agbot))
				if _, err := exchangeHandler.Delete("orgs/"+agbotOrg+"/agbots/"+agbot+"/patterns/"+patternId, cliutils.OrgAndCreds(org, userPwCreds)); err != nil {
					return err
				}
			}
		}

		// Load and remove all agbot served business policies associated with this org
		polResp := new(exchange.GetAgbotsBusinessPolsResponse)
		if _, err := exchangeHandler.Get("orgs/"+agbotOrg+"/agbots/"+agbot+"/businesspols", cliutils.OrgAndCreds(org, userPwCreds), polResp); err != nil {
			return err
		}

		for polId, p := range polResp.BusinessPols {
			if p.BusinessPolOrg == theOrg { // the nodeOrg and polOrg are the same
				cliutils.Verbose(msgPrinter.Sprintf("Removing policy %s from agbot %s", polId, agbot))
				if _, err := exchangeHandler.Delete("orgs/"+agbotOrg+"/agbots/"+agbot+"/businesspols/"+polId, cliutils.OrgAndCreds(org, userPwCreds)); err != nil {
					return err
				}
			}
		}
	}

	// Search exchange for org and delete it.
	cliutils.Verbose(msgPrinter.Sprintf("Deleting org %s from the Horizon Exchange...", theOrg))
	if _, err := exchangeHandler.Delete("orgs/"+theOrg, cliutils.OrgAndCreds(org, userPwCreds)); err != nil {
		return err
	}
	msgPrinter.Printf("Org %v is deleted from the Horizon Exchange", theOrg)
	msgPrinter.Println()

	// Delete org and clean up resources for this org in MMS
	cliutils.Verbose(msgPrinter.Sprintf("Deleting org %s from MMS...", theOrg))
	if _, err := mmsHandler.Delete("api/v1/organizations/"+theOrg, cliutils.OrgAndCreds(org, userPwCreds)); err != nil {
		return err
	}
	msgPrinter.Printf("Org %v is deleted from MMS", theOrg)
	msgPrinter.Println()

	msgPrinter.Printf("Organization %v is successfully removed.", theOrg)
	msgPrinter.Println()

	return nil
}

// validate the heartbeat input values and return the new values to update
func getNewHeartbeatAttributes(min, max, adjust int, existingInterv *exchange.HeartbeatIntervals) (int, int, int) {
	// get message printer
	msgPrinter := i18n.GetMessagePrinter()

	// check constraints
	// if any invalid values for heartbeat, throw error
	negFlags := []string{}
	if min < -1 {
		negFlags = append(negFlags, "--heartbeatmin")
	}
	if max < -1 {
		negFlags = append(negFlags, "--heartbeatmax")
	}
	if adjust < -1 {
		negFlags = append(negFlags, "--heartbeatadjust")
	}
	if len(negFlags) > 0 {
		return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, msgPrinter.Sprintf("Invalid input for %v. Only -1, 0 and positive integers are allowed.", strings.Join(negFlags, ",")))
	}

	// if min is not less than or equal to max from pure user input, throw error
	if min > 0 && max > 0 && min > max {
		return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, msgPrinter.Sprintf("The value for --heartbeatmin must be less than or equal to the value for --heartbeatmax."))
	}

	// use the existing value if it is -1
	var old_heartbeats exchange.HeartbeatIntervals
	if existingInterv != nil {
		old_heartbeats = *existingInterv
	}
	if min == -1 {
		min = old_heartbeats.MinInterval
	}
	if max == -1 {
		max = old_heartbeats.MaxInterval
	}
	if adjust == -1 {
		adjust = old_heartbeats.IntervalAdjustment
	}

	// if min is not less than or equal to max from the final combined values, throw error
	if min > 0 && max > 0 && min > max {
		return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, msgPrinter.Sprintf("The value for heartbeat minInterval (%v) must be less than or equal to the value for heartbeat maxInterval (%v).", min, max))
	}

	return min, max, adjust
}

// convert the tags from an array of mytag=myvalue into a map.
// return nil if the input array is empty
func convertTags(tags []string, update bool) map[string]string {
	// get message printer
	msgPrinter := i18n.GetMessagePrinter()

	if tags == nil || len(tags) == 0 {
		return nil
	}

	orgTags := map[string]string{}
	for _, tag := range tags {
		if update && tag == "" {
			msgPrinter.Printf("Empty string is specified with -t, all tags will be removed.")
			msgPrinter.Println()
			return orgTags
		}

		t := strings.SplitN(tag, "=", 2)
		if len(t) != 2 {
			return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, msgPrinter.Sprintf("Invalid input for -t or --tag flag: %v. The valid format is '-t mytag=myvalue' or '--tag mytag=myvalue'.", tag))
		} else {
			orgTags[t[0]] = t[1]
		}
	}
	return orgTags
}

// This function checks if the given agbot exists or not
func CheckAgbot(org string, userPw string, agbot string, exchangeHandler cliutils.ServiceHandler) error {
	// get message printer
	msgPrinter := i18n.GetMessagePrinter()
	if agbot == "" {
		return nil
	}

	agOrg, ag1, err := cliutils.TrimOrg(org, agbot)
	if err != nil {
		return err
	}
	var agbots ExchangeAgbots
	if httpCode, err := exchangeHandler.Get("orgs/"+agOrg+"/agbots"+cliutils.AddSlash(ag1), cliutils.OrgAndCreds(org, userPw), &agbots); err != nil {
		return err
	} else if httpCode == 404 {
		return cliutils.CLIError{StatusCode: cliutils.NOT_FOUND, msgPrinter.Sprintf("Agbot '%v/%v' specified by -a cannot be not found in the Exchange", agOrg, ag1))
	}

	return nil
}

// This function goes through all the orgs and get the agbots for that org.
// It returns the first agbot it found.
func GetDefaultAgbot(org, userPwCreds string, exchangeHandler cliutils.ServiceHandler) (string, error) {
	// get all the orgs
	var orgs ExchangeOrgs
	if _, err := exchangeHandler.Get("orgs", cliutils.OrgAndCreds(org, userPwCreds), &orgs); err != nil {
		return "", err
	}

	// for each org find agbots
	for o := range orgs.Orgs {
		var resp ExchangeAgbots
		if httpCode, err := exchangeHandler.Get("orgs/"+o+"/agbots", cliutils.OrgAndCreds(org, userPwCreds), &resp); err != nil {
			return "", err
		} else if httpCode == 200 {
			for a := range resp.Agbots {
				return a, nil
			}
		}
	}

	return "", nil
}

// Add the given org to the given agbot's served pattern and served policy list.
func AddOrgToAgbotServingList(org, userPw, theOrg, agbot string, exchangeHandler cliutils.ServiceHandler) error {
	var agbotOrg string
	var err error
	if agbotOrg, agbot, err = cliutils.TrimOrg(org, agbot); err != nil {
		return err
	}

	// http code 201 means success, 409 means it already exists
	inputPat := ServedPattern{PatternOrg: theOrg, Pattern: "*", NodeOrg: theOrg}
	if _, err := exchangeHandler.Post("orgs/"+agbotOrg+"/agbots/"+agbot+"/patterns", cliutils.OrgAndCreds(org, userPw), inputPat, nil); err != nil {
		return err
	}

	inputPol := exchange.ServedBusinessPolicy{BusinessPolOrg: theOrg, BusinessPol: "*", NodeOrg: theOrg}
	if _, err := exchangeHandler.Post("orgs/"+agbotOrg+"/agbots/"+agbot+"/businesspols", cliutils.OrgAndCreds(org, userPw), inputPol, nil); err != nil {
		return err
	}

	return nil
}
