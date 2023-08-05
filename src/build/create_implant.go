package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"../helpers"
)

func main() {
	helpers.NicePrinting("info", "Welcome to the implant creator :)")
	helpers.NicePrinting("info","Please insert the path to the configuration file")

	var configPath string
	// Read the implant configuration path
	_, err := fmt.Scanf("%s", &configPath)
	if err != nil {
		panic(err.Error())

	}
	// Open the file
	configFile, err := os.Open(configPath)
	if err != nil {
		panic(err)
	}

	helpers.NicePrinting("info","Please insert the path to the implant file")
	var implantPath string
	// Read the implant template source code
	_, err = fmt.Scanf("%s", &implantPath)
	if err != nil {
		panic(err.Error())
	}

	// Close on exit
	defer configFile.Close()
	// Open the file
	implantFile, err := os.Open(implantPath)
	if err != nil {
		panic(err)
	}
	// Close on exit
	defer implantFile.Close()

	// Read both files
	configBytes, _ := ioutil.ReadAll(configFile)
	implantBytes, _ := ioutil.ReadAll(implantFile)

	implantCode := string(implantBytes)
	// Parse the JSON
	var configuration map[string]map[string]interface{}
	err = json.Unmarshal(configBytes, &configuration)
	if err != nil {
		panic(err)
	}

	// Headers
	getReqHeaders := configuration["GETRequest"]
	postReqHeaders := configuration["POSTRequest"]

	// Listener details
	endpoints := configuration["Endpoint"]["Name"].(string)
	endpointAddress := configuration["Endpoint"]["Address"].(string)
	listenerUUID := configuration["Endpoint"]["UUID"].(string)

	// Options
	jitter := configuration["Options"]["Jitter"].(string)
	maxRetry := configuration["Options"]["MaxRetry"].(string)
	sleepTime := configuration["Options"]["SleepTime"].(string)
	killDate := configuration["Options"]["KillDate"].(string)

	// Encryption
	aesKey := configuration["Options"]["AESKey"].(string)
	hmacKey := configuration["Options"]["HMACKey"].(string)

	// Do some trickery to format the headers
	var postHeaders string
	counter := 0
	for index, value := range postReqHeaders{
		postHeaders += index + "-->" + value.(string) 
		counter++
		if counter == len(postReqHeaders) {
			break
		}
		postHeaders += "<--"
	}
	
	var getHeaders string
	counter = 0
	for index, value := range getReqHeaders {
		getHeaders += index + "-->" + value.(string) 
		counter++
		if counter == len(getReqHeaders) {
			break
		}
		getHeaders += "<--"
	}

	// Replace all the things
	implantCode = strings.Replace(implantCode, "claddr", endpointAddress, -1)
	implantCode = strings.Replace(implantCode, "ckilldate", killDate, -1)
	implantCode = strings.Replace(implantCode, "csleeptime", sleepTime, -1)
	implantCode = strings.Replace(implantCode, "caesk", aesKey, -1)
	implantCode = strings.Replace(implantCode, "chmack", hmacKey, -1)
	implantCode = strings.Replace(implantCode, "cjitter", jitter, -1)
	implantCode = strings.Replace(implantCode, "cendpoints", endpoints, -1)
	implantCode = strings.Replace(implantCode, "cmaxretry", maxRetry, -1)
	implantCode = strings.Replace(implantCode, "cluuid", listenerUUID, -1)
	implantCode = strings.Replace(implantCode, "cgetheaders", postHeaders, -1)
	implantCode = strings.Replace(implantCode, "cpostheaders", getHeaders, -1)

	// Read the output file path and write to it
	helpers.NicePrinting("info","Please enter the name you'd like the code to be saved to")
	var implantNewCodePath string
	_, err = fmt.Scanf("%s", &implantNewCodePath)
	if err != nil {
		panic(err)
	}

	implantF, err := os.Create(implantNewCodePath)
	if err != nil {
		panic(err)
	}
	// Close on exit
	defer implantF.Close()
	// Write source code
	_, err = implantF.WriteString(implantCode)
	if err != nil {
		panic(err)
	}

	helpers.NicePrinting("plus", "The implant has been saved, you can now compile it")
}
