package utilcmds

import (
	"fmt"
	"github.com/open-horizon/anax/cli/cliconfig"
	"github.com/open-horizon/anax/cli/cliutils"
	"github.com/open-horizon/anax/i18n"
	"github.com/open-horizon/rsapss-tool/sign"
	"github.com/open-horizon/rsapss-tool/verify"
	"os"
)

func Sign(privKeyFilePath string) error {
	stdinBytes, err := cliutils.ReadStdin()
	if err != nil {
		return err
	}
	signature, err := sign.Input(privKeyFilePath, stdinBytes)
	if err != nil {
		return cliutils.CLIError{StatusCode: cliutils.CLI_GENERAL_ERROR, i18n.GetMessagePrinter().Sprintf("problem signing stdin with %s: %v", privKeyFilePath, err))
	}
	fmt.Println(signature)

	return nil
}

func Verify(pubKeyFilePath, signature string) error {
	// get message printer
	msgPrinter := i18n.GetMessagePrinter()

	stdinBytes, err := cliutils.ReadStdin()
	if err != nil {
		return err
	}
	verified, err := verify.Input(pubKeyFilePath, signature, stdinBytes)
	if err != nil {
		return cliutils.CLIError{StatusCode: cliutils.CLI_GENERAL_ERROR, msgPrinter.Sprintf("problem verifying deployment string with %s: %v", pubKeyFilePath, err))
	} else if !verified {
		msgPrinter.Printf("This is not a valid signature for stdin.")
		msgPrinter.Println()
		os.Exit(cliutils.SIGNATURE_INVALID)
	} else {
		msgPrinter.Printf("Signature is valid.")
		msgPrinter.Println()
	}

	return nil
}

// convert the given json file to shell export commands and output it to stdout
func ConvertConfig(configFile string) error {
	if configFile == "" {
		projectConfigFile, err := cliconfig.GetProjectConfigFile("")
		if err != nil {
			return cliutils.CLIError{StatusCode: cliutils.CLI_GENERAL_ERROR, i18n.GetMessagePrinter().Sprintf("Failed to get project configuration file. Error: %v", err))
		}
		if projectConfigFile == "" {
			return cliutils.CLIError{StatusCode: cliutils.CLI_GENERAL_ERROR, i18n.GetMessagePrinter().Sprintf("Please use the -f flag to specify a configuration file."))
		}
		configFile = projectConfigFile
	}
	// get the env vars from the file
	hzn_vars, metadata_vars, err := cliconfig.GetVarsFromFile(configFile)
	if err != nil && !os.IsNotExist(err) {
		return cliutils.CLIError{StatusCode: cliutils.CLI_GENERAL_ERROR, i18n.GetMessagePrinter().Sprintf("Failed to get the variables from configuration file %v. Error: %v", configFile, err))
	}

	// convert it to shell commands
	for k, v := range hzn_vars {
		fmt.Printf("export %v=%v\n", k, v)
	}
	for k, v := range metadata_vars {
		fmt.Printf("export %v=%v\n", k, v)
	}

	return nil
}
