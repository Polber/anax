package exchange

import (
	"encoding/json"
	"fmt"
	"github.com/open-horizon/anax/cli/cliutils"
	"github.com/open-horizon/anax/i18n"
	"github.com/open-horizon/anax/semanticversion"
	"strings"
)

const USER_EMAIL_OPTIONAL_EXCHANGE_VERSION = "2.61.0"

type ExchangeUsers struct {
	Users     map[string]ExchangeUser `json:"users"`
	ListIndex int                     `json:"lastIndex"`
}

type ExchangeUser struct {
	Password    string `json:"password"`
	Email       string `json:"email,omitempty"`
	Admin       bool   `json:"admin"`
	HubAdmin    bool   `json:"hubAdmin"`
	LastUpdated string `json:"lastUpdated"`
	UpdatedBy   string `json:"updatedBy"`
}

func UserList(org, userPwCreds, theUser string, allUsers, namesOnly bool, exchangeHandler cliutils.ServiceHandler) error {
	// get message printer
	msgPrinter := i18n.GetMessagePrinter()

	cliutils.SetWhetherUsingApiKey(userPwCreds)

	// Decide which users should be shown
	var err error
	if allUsers {
		theUser = ""
	} else if theUser == "" {
		theUser, _ = cliutils.SplitIdToken(userPwCreds)
		if _, theUser, err = cliutils.TrimOrg("", theUser); err != nil {
			return err
		}
	} // else we list the user specified in theUser

	// Get users
	var users ExchangeUsers
	if httpCode, err := exchangeHandler.Get("orgs/"+org+"/users"+cliutils.AddSlash(theUser), cliutils.OrgAndCreds(org, userPwCreds), &users); err != nil {
		return err
	} else if httpCode == 404 {
		return cliutils.CLIError{StatusCode: cliutils.NOT_FOUND, msgPrinter.Sprintf("user '%s' not found in org %s", strings.TrimPrefix(theUser, "/"), org))
	}

	// Decide how much of each user should be shown
	if namesOnly {
		usernames := []string{} // this is important (instead of leaving it nil) so json marshaling displays it as [] instead of null
		for u := range users.Users {
			usernames = append(usernames, u)
		}
		jsonBytes, err := json.MarshalIndent(usernames, "", cliutils.JSON_INDENT)
		if err != nil {
			return cliutils.CLIError{StatusCode: cliutils.JSON_PARSING_ERROR, msgPrinter.Sprintf("failed to marshal 'exchange user list' output: %v", err))
		}
		fmt.Printf("%s\n", jsonBytes)
	} else { // show full resources
		output, err := cliutils.MarshalIndent(users.Users, "exchange users list")
		if err != nil {
			return err
		}
		fmt.Println(output)
	}

	return nil
}

func UserCreate(org, userPwCreds, user, pw, email string, isAdmin bool, isHubAdmin bool, exchangeHandler cliutils.ServiceHandler) error {
	// get message printer
	msgPrinter := i18n.GetMessagePrinter()

	var emailIsOptional bool
	var err error
	if emailIsOptional, err = checkExchangeVersionForOptionalUserEmail(org, userPwCreds, exchangeHandler); err != nil {
		return cliutils.CLIError{StatusCode: cliutils.CLI_GENERAL_ERROR, msgPrinter.Sprintf("failed to check exchange version, error: %v", err))
	}

	if email == "" && strings.Contains(user, "@") {
		email = user
	} else if email == "" && !emailIsOptional {
		return cliutils.CLIError{StatusCode: cliutils.CLI_INPUT_ERROR, msgPrinter.Sprintf("an email must be specified because the Exchange API version is less than %v.", USER_EMAIL_OPTIONAL_EXCHANGE_VERSION))
	}

	if isHubAdmin && org != "root" {
		return cliutils.CLIError{StatusCode: cliutils.CLI_GENERAL_ERROR, msgPrinter.Sprintf("Only users in the root org can be hubadmins."))
	}

	if !isHubAdmin && org == "root" {
		return cliutils.CLIError{StatusCode: cliutils.CLI_GENERAL_ERROR, msgPrinter.Sprintf("Users in the root org must be hubadmins. Omit the -H option."))
	}

	cliutils.SetWhetherUsingApiKey(userPwCreds)

	postUserReq := cliutils.UserExchangeReq{Password: pw, Admin: isAdmin, HubAdmin: isHubAdmin, Email: email}
	if _, err = exchangeHandler.Post("orgs/"+org+"/users/"+user, cliutils.OrgAndCreds(org, userPwCreds), postUserReq, nil); err != nil {
		return err
	}

	return nil
}

type UserExchangePatchAdmin struct {
	Admin bool `json:"admin"`
}

func UserSetAdmin(org, userPwCreds, user string, isAdmin bool, exchangeHandler cliutils.ServiceHandler) error {
	msgPrinter := i18n.GetMessagePrinter()

	if isAdmin && org == "root" {
		return cliutils.CLIError{StatusCode: cliutils.CLI_GENERAL_ERROR, msgPrinter.Sprintf("A user in the root org cannot be an org admin."))
	}

	cliutils.SetWhetherUsingApiKey(userPwCreds)
	patchUserReq := UserExchangePatchAdmin{Admin: isAdmin}
	if _, err := exchangeHandler.Patch("orgs/"+org+"/users/"+user, cliutils.OrgAndCreds(org, userPwCreds), patchUserReq, nil); err != nil {
		return err
	}

	return nil
}

func UserRemove(org, userPwCreds, user string, force bool, exchangeHandler cliutils.ServiceHandler) error {
	cliutils.SetWhetherUsingApiKey(userPwCreds)
	if !force {
		cliutils.ConfirmRemove(i18n.GetMessagePrinter().Sprintf("Warning: this will also delete all Exchange resources owned by this user (nodes, services, patterns, etc). Are you sure you want to remove user %v/%v from the Horizon Exchange?", org, user))
	}

	if httpCode, err := exchangeHandler.Delete("orgs/"+org+"/users/"+user, cliutils.OrgAndCreds(org, userPwCreds)); err != nil {
		return err
	} else if httpCode == 404 {
		return cliutils.CLIError{StatusCode: cliutils.NOT_FOUND, i18n.GetMessagePrinter().Sprintf("user '%s' not found in org %s", user, org))
	}

	return nil
}

// check if current exchange version is greater than 2.61.0, which makes user email optional.
// return (true, nil) if user email is optional
// return (false, nil) if user email is required
func checkExchangeVersionForOptionalUserEmail(org, userPwCreds string, exchangeHandler cliutils.ServiceHandler) (bool, error) {
	cliutils.SetWhetherUsingApiKey(userPwCreds)

	var output []byte
	if _, err := exchangeHandler.Get("admin/version", cliutils.OrgAndCreds(org, userPwCreds), &output); err != nil {
		return false, err
	}

	exchangeVersion := strings.TrimSpace(string(output))

	if !semanticversion.IsVersionString(exchangeVersion) {
		return false, fmt.Errorf("The current exchange version %v is not a valid version string.", exchangeVersion)
	} else if comp, err := semanticversion.CompareVersions(exchangeVersion, USER_EMAIL_OPTIONAL_EXCHANGE_VERSION); err != nil {
		return false, fmt.Errorf("Failed to compare the versions. %v", err)
	} else if comp < 0 {
		// current exchange version < 2.61.0. User email is required
		return false, nil
	} else {
		// current exchange version >= 2.61.0. User email is optional
		return true, nil
	}

}
