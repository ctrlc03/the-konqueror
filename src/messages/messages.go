package messages

import (
	"github.com/olekukonko/tablewriter"
	uuid "github.com/satori/go.uuid"
	"os"
	"strconv"
	"time"
)

// Login message
type Login struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Admin can use this to register a new user
type NewOperator struct {
	AdminUsername  string `json:"admin_username"`
	AdminPassword  string `json:"admin_password"`
	NewUsername    string `json:"operator_username"`
	NewPassword    string `json:"operator_password"`
}

// A default message type
type Message struct {
	Message 	 interface{}  	 `json:"message"`
	Type    	 string 		 		 `json:"type,omitempty"`
	ListenerUUID uuid.UUID 		 `json:"listener_uuid,omitempty"`
}

// A Listener message
type Listener struct {
	Type			string   	`json:"type"`
	UUID        	uuid.UUID	`json:"uuid,omitempty"`
	AESKey          string   	`json:"aeskey,omitempty"`
	HMACKey         string      `json:"hmackey,omitempty"`
}

// A task for the implant
type Task struct {
	Type		 string		`json:"type,omitempty"`
	UUID         uuid.UUID	`json:"uuid,omitempty"`
	Args 		 []string   `json:"args,omitempty"`
	Result       string     `json:"result,omitempty"`
	ListenerUUID uuid.UUID  `json:"luuid,omitempty"`
	ImplantUUID  uuid.UUID  `json:"iuuid,omitempty"`
	Success		 bool		`json:"success,omitempty"`
	Date         string     `json:"date,omitempty"`
}

// Describes the implants details to be exchanged with the client
type Implant struct {
	UUID            uuid.UUID 		`json:"uuid"`
	CWD             string    		`json:"cwd"`
	OS              string    		`json:"os"`
	Arch            string    		`json:"arch"`
	Jitter          int       		`json:"jitter"`
	UserID          string    		`json:"userid"`
	Hostname        string    		`json:"hostname"`
	FailedCheckIn   int       		`json:"failedcheckin"`
	MaxRetry        int       		`json:"maxretry"`
	PID             int       		`json:"pid"`
	PPID            int             `json:"ppid"`
	Username        string    		`json:"username"`
	SleepTime       time.Duration	`json:"sleeptime"`
	ListenerUUID    uuid.UUID		`json:"luuid,omitempty"`
	Status          string 			`json:"status"`
	KillDate        int64 			`json:"killdate"`
	Type            string          `json:"type"`
}

// A message from implant to listener
type C2Message struct {
	Message interface{}		`json:"message"`
	HMAC    string			`json:"hmac"`
	Type    string 			`json:"type"`
	ListenerUUID uuid.UUID  `json:"uuid"`
	ListenerType string     `json:"ltype"`
}

// Method to print system info for implant
func (implant *Implant) PrintSysInfo() {

	table := tablewriter.NewWriter(os.Stdout)
	// Set headers
	table.SetHeader([]string{
		"OPTION", "VALUE",
	})

	// Set data that we need
	data := [][]string {
		{"CWD", implant.CWD},
		{"Hostname", implant.Hostname},
		{"Username", implant.Username},
		{"UserID", implant.UserID},
		{"PID",strconv.Itoa(implant.PID)},
		{"PPID", strconv.Itoa(implant.PPID)},
		{"OS",  implant.OS},
		{"Arch", implant.Arch},
	}


	for _, v := range data {
		table.Append(v)
	}

	// Print table to STDOUT
	table.Render()
}

// Method to print implant's info
func (implant *Implant) PrintImplantInfo(){
	table := tablewriter.NewWriter(os.Stdout)
	// Set headers
	table.SetHeader([]string{
		"OPTION", "VALUE",
	})

	killDate := time.Unix(implant.KillDate, 0)

	// Set data that we need
	data := [][]string {
		{"UUID", implant.UUID.String()},
		{"Type", implant.Type},
		{"Failed Check ins", strconv.Itoa(implant.FailedCheckIn)},
		{"Max Retry", strconv.Itoa(implant.MaxRetry)},
		{"Sleep Time", implant.SleepTime.String()},
		{"Jitter", strconv.Itoa(implant.Jitter)},
		{"Listener UUID", implant.ListenerUUID.String()},
		{"Kill Date", killDate.String()},
	}

	for _, v := range data {
		table.Append(v)
	}

	// Print table to STDOUT
	table.Render()
}
