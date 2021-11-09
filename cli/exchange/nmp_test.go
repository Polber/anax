package exchange

import (
	"strings"
	"testing"

	"github.com/open-horizon/anax/cli/cliutils"
	"github.com/open-horizon/anax/cli/testutils"
	"github.com/open-horizon/anax/exchange"
	"github.com/open-horizon/anax/exchangecommon"
	"github.com/stretchr/testify/assert"
)

//------------------------------------------------//

const TESTNMP = "test-nmp"
const TESTNMP2 = "test-nmp-2"

// Mock Exchange handler
type TestExchangeHandlerNMP struct {
	testutils.TestExchangeHandler
}

// Second mock Exchange handler
type TestExchangeHandlerNMP2 struct {
	testutils.TestExchangeHandler
}

// GET function for mocking an Exchange with TWO nmp's stored
func (e TestExchangeHandlerNMP) Get(url, credentials string, structure interface{}) (httpCode int, err error) {
	// Run parent GET function first
	var code int
	if code, err = e.TestExchangeHandler.Get(url, credentials, structure); err != nil {
		return
	} else if code != 200 {
		return code, nil
	}

	// Get nmp name, if given
	givenNMPName := strings.Replace(url, "orgs/"+testutils.ORGAUTH+"/managementpolicies", "", -1)
	givenNMPName = strings.Replace(givenNMPName, "/", "", 1)

	// Return 404 if given nmp name is not empty and doesn't equal TESTNMP or TESTNMP2
	if givenNMPName != "" && givenNMPName != TESTNMP && givenNMPName != TESTNMP2 {
		return 404, nil
	}

	// Construct sample response
	policies := make(map[string]exchangecommon.ExchangeNodeManagementPolicy)
	if givenNMPName == TESTNMP || givenNMPName == "" {
		policies[TESTNMP] = exchangecommon.ExchangeNodeManagementPolicy{}
	}
	if givenNMPName == TESTNMP2 || givenNMPName == "" {
		policies[TESTNMP2] = exchangecommon.ExchangeNodeManagementPolicy{}
	}
	structure.(*exchange.ExchangeNodeManagementPolicyResponse).Policies = policies

	return code, nil
}

// Second GET function for mocking an Exchange with ZERO nmp's stored
func (e TestExchangeHandlerNMP2) Get(url, credentials string, structure interface{}) (httpCode int, err error) {
	// Run parent GET function first
	var code int
	if code, err = e.TestExchangeHandler.Get(url, credentials, structure); err != nil {
		return
	} else if code != 200 {
		return code, nil
	}

	// No NMP's exist in this Exchange
	return 404, nil
}

func (e TestExchangeHandlerNMP) Put(url, credentials string, body interface{}, structure interface{}) (httpCode int, err error) {
	// Run parent PUT function first
	var code int
	if code, err = e.TestExchangeHandler.Put(url, credentials, body, structure); err != nil {
		return
	} else if code != 201 {
		return code, nil
	}

	return code, nil
}

func (e TestExchangeHandlerNMP) Post(url, credentials string, body interface{}, structure interface{}) (httpCode int, err error) {
	// Run parent POST function first
	var code int
	if code, err = e.TestExchangeHandler.Post(url, credentials, body, structure); err != nil {
		return
	} else if code != 201 {
		return code, nil
	}

	return code, nil
}

func (e TestExchangeHandlerNMP) Delete(url, credentials string) (httpCode int, err error) {
	// Run parent DELETE function first
	var code int
	if code, err = e.TestExchangeHandler.Delete(url, credentials); err != nil {
		return
	} else if code != 204 {
		return code, nil
	}

	return code, nil
}

// NMPList(org, credToUse, nmpName string, namesOnly bool, exHandler cliutils.ExchangeHandler)
func TestNMPList(t *testing.T) {
	var err error
	err = NMPList(testutils.ORGAUTH, testutils.CREDTOUSEAUTH, "", true, TestExchangeHandlerNMP{})
	assert.Equal(t, nil, err, "")
	err = NMPList(testutils.ORGAUTH, testutils.CREDTOUSEAUTH, "", true, TestExchangeHandlerNMP2{})
	assert.Equal(t, nil, err, "")
	err = NMPList(testutils.ORGAUTH, testutils.CREDTOUSEAUTH, "fake-nmp", true, TestExchangeHandlerNMP2{})
	assert.Equal(t, cliutils.NOT_FOUND, err.(cliutils.CLIError).StatusCode, "")
	err = NMPList(testutils.ORGAUTH, testutils.CREDTOUSEAUTH, "*", true, TestExchangeHandlerNMP2{})
	assert.Equal(t, nil, err, "")
	err = NMPList(testutils.ORGAUTH, testutils.CREDTOUSEAUTH, "test-nmp", true, TestExchangeHandlerNMP{})
	assert.Equal(t, nil, err, "")
	err = NMPList(testutils.ORGAUTH, testutils.CREDTOUSEAUTH, "fake-nmp", true, TestExchangeHandlerNMP{})
	assert.Equal(t, cliutils.NOT_FOUND, err.(cliutils.CLIError).StatusCode, "")
	err = NMPList("fake", "fake", "fake-nmp", true, TestExchangeHandlerNMP{})
	assert.Equal(t, cliutils.HTTP_ERROR, err.(cliutils.CLIError).StatusCode, "")
	err = NMPList("fake", "fake", "", true, TestExchangeHandlerNMP{})
	assert.Equal(t, cliutils.HTTP_ERROR, err.(cliutils.CLIError).StatusCode, "")
}

// NMPAdd(org, credToUse, nmpName, jsonFilePath string, noConstraints bool, exHandler cliutils.ExchangeHandler)
func TestNMPAdd(t *testing.T) {

}

// NMPRemove(org, credToUse, nmpName string, force bool, exHandler cliutils.ExchangeHandler)
func TestNMPRemove(t *testing.T) {

}

// NMPNew()
func TestNMPNew(t *testing.T) {
	NMPNew()
}
