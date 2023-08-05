package dao

import (
	"database/sql"
	"errors"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	uuid "github.com/satori/go.uuid"
	"strconv"
	"strings"
	"time"

	"../messages"

)

// Define a DAO Struct
type DAO struct {
	DBPath string
}

// Method to validate the API Key
func (dao *DAO) ValidateAPIKey(APIKey string) error {

	// Open DB
	db, err := sql.Open("sqlite3", dao.DBPath)
	if err != nil {
		return err
	}
	defer db.Close()
	// Create prepared statement
	statement, err := db.Prepare("SELECT username from users WHERE api_key=?;")
	if err != nil {
		return err
	}

	defer statement.Close()

	var dummy string
	// Execute statement
	err = statement.QueryRow(APIKey).Scan(&dummy)

	// Check errors and result of query
	if err != nil {
		return err
	}

	if dummy != "" {
		return nil
	}

	return errors.New("API Key not valid")
}

// Method to insert a new Listener into the DB
func (dao *DAO) InsertNewListener(listener messages.Listener) error {

	// Connect DB
	db, err := sql.Open("sqlite3", dao.DBPath)
	if err != nil {
		return err
	}
	defer db.Close()
	// Prepare statement
	statement, err := db.Prepare("INSERT INTO listeners VALUES(?,?,?,?);")
	if err != nil {
		return err
	}
	defer statement.Close()
	// Exec statement
	result, err := statement.Exec(listener.UUID, listener.Type, listener.AESKey, listener.HMACKey)
	if err != nil {
		return err
	}

	// Check rows affected
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected != 1 {
		return errors.New("Failed to insert a new listener")
	}

	return nil

}

// Method to Login the operator
func (dao *DAO) Login(username, password string) (string, error) {

	// Open the DB
	db, err := sql.Open("sqlite3", dao.DBPath)
	if err != nil {
		return "", err
	}
	defer db.Close()
	// Create prepared statement
	statement, err := db.Prepare("SELECT api_key FROM users WHERE username=? AND password=? AND logged_in=0;")
	if err != nil {
		return "", err
	}

	defer statement.Close()
	var apiKey string

	// Execute query
	err = statement.QueryRow(username, password).Scan(&apiKey)

	if err != nil {
		return "", err
	}

	return apiKey, nil

}

// Method to update login status of an operator
func (dao *DAO) UpdateLogin(status int, api_key string) error {

	db, err := sql.Open("sqlite3", dao.DBPath)
	if err != nil {
		return err
	}
	defer db.Close()
	statement, err := db.Prepare("UPDATE users SET logged_in=? WHERE api_key=?;")
	if err != nil {
		return err
	}
	defer statement.Close()
	result, err := statement.Exec(status, api_key)
	if err != nil {
		return err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected != 1 {
		return errors.New("failed to update login status")
	}
	return nil
}

// Check admin password
func (dao *DAO) AdminLogin(username, password string) bool {

	// Open the DB
	db, err := sql.Open("sqlite3", dao.DBPath)
	if err != nil {
		return false
	}
	defer db.Close()
	// Create prepared statement
	statement, err := db.Prepare("SELECT username FROM users WHERE username=? AND password=? AND is_admin=1;")
	if err != nil {
		fmt.Println(err)
		return false
	}

	defer statement.Close()

	var adm string

	// Execute query
	err = statement.QueryRow(username, password).Scan(&adm)
	if err != nil {
		fmt.Println(err)
		return false
	}

	return true

}

// Method to save new operator details on the DB
func (dao *DAO) InsertNewOperator(username, password string) error {

	db, err := sql.Open("sqlite3", dao.DBPath)
	if err != nil {
		return err
	}
	defer db.Close()
	statement, err := db.Prepare("INSERT INTO users (username, password, is_admin, api_key, logged_in) VALUES(?,?,0,?,0)")
	if err != nil {
		return err
	}

	defer statement.Close()

	// Create API Key
	apiKey := uuid.Must(uuid.NewV4()).String()
	result, err := statement.Exec(username, password, apiKey)
	if err != nil {
		return err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected != 1 {
		return errors.New("Failed to create a new operator")
	}

	return nil

}

// Method to insert implant data into the DB
func (dao *DAO) InsertImplantData(implantData messages.Implant) error {

	db, err := sql.Open("sqlite3", dao.DBPath)
	if err != nil {
		return err
	}
	defer db.Close()
	// Prepare statement
	statement, err := db.Prepare("INSERT INTO implants VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);")
	if err != nil {
		return err
	}
	defer statement.Close()
	// Exec query
	result, err := statement.Exec(
		implantData.UUID,
		implantData.CWD,
		implantData.Hostname,
		implantData.Username,
		implantData.UserID,
		implantData.FailedCheckIn,
		implantData.MaxRetry,
		implantData.PID,
		implantData.Arch,
		implantData.OS,
		implantData.SleepTime,
		implantData.Jitter,
		implantData.ListenerUUID,
		implantData.Status,
		implantData.KillDate,
		implantData.PPID,
		implantData.Type,
		)

	if err != nil {
		return nil
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected != 1 {
		return errors.New("failed to insert a new implant data")
	}

	return nil
}

// Method to insert task into DB
func (dao *DAO) InsertTask(task messages.Task) error {
	db, err := sql.Open("sqlite3", dao.DBPath)
	if err != nil {
		return err
	}
	defer db.Close()
	statement, err := db.Prepare(
		"INSERT INTO tasks VALUES(?,?,?,?,?,?,?,?,'created');")
	if err != nil {
		return err
	}
	defer statement.Close()
	result, err := statement.Exec(
		task.UUID,
		task.Type,
		strings.Join(task.Args, " "),
		task.Result,
		task.ListenerUUID.String(),
		task.ImplantUUID.String(),
		strconv.FormatBool(task.Success),
		task.Date,
	)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return nil
	}
	if rows != 1 {
		return errors.New("failed to insert a task")
	}
	return nil
}

// Method to retrieve a listener UUID from an implant UUID
func (dao *DAO) GetListenerUUIDFromImplantUUID(implantUUID string) (string, error) {
	db, err := sql.Open("sqlite3", dao.DBPath)
	if err != nil {
		return "", err
	}
	defer db.Close()
	statement, err := db.Prepare("SELECT listener_uuid FROM implants WHERE uuid=?;")
	if err != nil {
		return "", err
	}
	defer statement.Close()
	var listenerUUID string
	result, err := statement.Query(implantUUID)
	if err != nil {
		return "", err
	}
	defer result.Close()
	for result.Next() {
		err = result.Scan(&listenerUUID)
		if err != nil {
			return "", err
		}
	}
	return listenerUUID, nil
}

// Method to retrieve all active listeners
func (dao *DAO) GetActiveListeners() ([]messages.Listener, error) {

	db, err := sql.Open("sqlite3", dao.DBPath)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	statement, err := db.Prepare("SELECT uuid, type FROM listeners;")
	if err != nil {
		return nil, err
	}

	defer statement.Close()
	rows, err := statement.Query()
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var listenerUuid, listenerType string
	var listeners []messages.Listener

	if rows != nil {
		for rows.Next() {
			err = rows.Scan(&listenerUuid, &listenerType)
			if err != nil {
				return nil, err
			}

			listeners = append(listeners, messages.Listener{
				Type:   listenerType,
				UUID:   uuid.Must(uuid.FromString(listenerUuid)),
			})
		}
	}

	return listeners, nil
}

// Method to retrieve one listener from the DB given the listener UUID
func (dao *DAO) GetListener(listenerUUID string) (messages.Listener, error) {
	var listener messages.Listener
	db, err := sql.Open("sqlite3", dao.DBPath)
	if err != nil {
		return listener, err
	}
	defer db.Close()
	statement, err := db.Prepare("SELECT uuid, type from listeners WHERE uuid=?;")
	if err != nil {
		return listener, err
	}
	defer statement.Close()
	result, err := statement.Query(listenerUUID)
	if err != nil {
		return listener, err
	}
	defer result.Close()
	var UUID, listenerType string

	if result != nil {
		for result.Next() {
			err = result.Scan(&UUID, &listenerType)
			if err != nil {
				return listener, err
			}
			listener = messages.Listener{
				Type:    listenerType,
				UUID:    uuid.Must(uuid.FromString(UUID)),
			}
		}
	}
	return listener, nil
}

// Method to retrieve the details of an implant
func (dao *DAO) GetImplant (listenerUUID string) (messages.Implant, error) {

	var implant messages.Implant

	db, err := sql.Open("sqlite3", dao.DBPath)
	if err != nil {
		return implant, err
	}
	defer db.Close()
	statement, err := db.Prepare("SELECT * FROM implants WHERE listener_uuid=? AND status='Active'")
	if err != nil {
		return implant, err
	}
	defer statement.Close()

	var UUID   			uuid.UUID
	var CWD    			string
	var OS  	        string
	var arch            string
	var jitter          int
	var userID          string
	var hostname        string
	var failedCheckIn   int
	var maxRetry        int
	var pid             int
	var username        string
	var sleepTime       time.Duration
	var lUUID    		uuid.UUID
	var status          string
	var killDate        int64
	var ppid            int
	var implantType     string

	rows, err := statement.Query(listenerUUID)
	if err != nil {
		return implant, err
	}
	defer rows.Close()
	if rows == nil {
		return implant, errors.New("error")
	}

	for rows.Next() {
		err = rows.Scan(
			&UUID,
			&CWD,
			&hostname,
			&username,
			&userID,
			&failedCheckIn,
			&maxRetry,
			&pid,
			&arch,
			&OS,
			&sleepTime,
			&jitter,
			&lUUID,
			&status,
			&killDate,
			&ppid,
			&implantType,
			)
		if err != nil {
			return implant, err
		}
		implant = messages.Implant{
			UUID:          UUID,
			CWD:           CWD,
			OS:            OS,
			Arch:          arch,
			Jitter:        jitter,
			UserID:        userID,
			Hostname:      hostname,
			FailedCheckIn: failedCheckIn,
			MaxRetry:      maxRetry,
			PID:           pid,
			PPID:          ppid,
			Username:      username,
			SleepTime:     sleepTime,
			ListenerUUID:  lUUID,
			Status:        status,
			KillDate:      killDate,
			Type:          implantType,
		}
	}
	return implant, nil
}

// Method to retrieve all implants from the DB
func (dao *DAO) GetActiveImplants() ([]messages.Implant, error) {
	var implants []messages.Implant
	db, err := sql.Open("sqlite3", dao.DBPath)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	statement, err := db.Prepare("SELECT * FROM implants WHERE status='Active';")
	if err != nil {
		return implants, err
	}
	defer statement.Close()
	rows, err := statement.Query()
	if err != nil {
		return implants, err
	}
	defer rows.Close()
	// Create all fields
	var UUID   			uuid.UUID
	var CWD    			string
	var OS  	        string
	var arch            string
	var jitter          int
	var userID          string
	var hostname        string
	var failedCheckIn   int
	var maxRetry        int
	var pid             int
	var username        string
	var sleepTime       time.Duration
	var lUUID    		uuid.UUID
	var status          string
	var killDate        int64
	var ppid            int
	var implantType     string

	if rows != nil {
		for rows.Next() {
			// Scan columns
			err = rows.Scan(
				&UUID,
				&CWD,
				&hostname,
				&username,
				&userID,
				&failedCheckIn,
				&maxRetry,
				&pid,
				&arch,
				&OS,
				&sleepTime,
				&jitter,
				&lUUID,
				&status,
				&killDate,
				&ppid,
				&implantType,
			)
			if err != nil {
				return implants, err
			}
			// Append a new implant
			implants = append(implants, messages.Implant{
				UUID:          UUID,
				CWD:           CWD,
				OS:            OS,
				Arch:          arch,
				Jitter:        jitter,
				UserID:        userID,
				Hostname:      hostname,
				FailedCheckIn: failedCheckIn,
				MaxRetry:      maxRetry,
				PID:           pid,
				PPID:          ppid,
				Username:      username,
				SleepTime:     sleepTime,
				ListenerUUID:  lUUID,
				Status:        status,
				KillDate:      killDate,
				Type:          implantType,
			})
		}
	}
	return implants, nil
}

// Method to retrieve the Encryption key and HMAC Key
func (dao *DAO) GetEncryptionKeys (listenerUUID string) (string, string, error) {
	db, err := sql.Open("sqlite3", dao.DBPath)
	if err != nil {
		return "", "", nil
	}
	defer db.Close()
	statement, err := db.Prepare("SELECT aes_key, hmac_key FROM listeners WHERE uuid=?;")
	if err != nil {
		return "", "", nil
	}
	defer statement.Close()
	var aes_key, hmac_key string
	result, err := statement.Query(listenerUUID)
	if err != nil {
		return "", "", nil
	}
	defer result.Close()
	for result.Next() {
		err := result.Scan(&aes_key, &hmac_key)
		if err != nil {
			return "", "", err
		}
	}

	return aes_key, hmac_key, nil
}

// Method to get task result
func (dao *DAO) GetTask(taskUUID uuid.UUID) (messages.Task, error) {
	var task messages.Task
	db, err := sql.Open("sqlite3", dao.DBPath)
	if err != nil {
		return task, err
	}
	defer db.Close()
	statement, err := db.Prepare("SELECT * FROM tasks WHERE uuid=? AND status='completed';")
	if err != nil {
		return task, err
	}
	defer statement.Close()
	var resultTaskUUID, taskType, arguments, taskResult, listenerUUID, implantUUID, success, taskDate, taskStatus string
	result, err := statement.Query(taskUUID.String())
	if err != nil {
		return task, err
	}
	defer result.Close()
	if result != nil {
		for result.Next() {
			err := result.Scan(
				&resultTaskUUID,
				&taskType,
				&arguments,
				&taskResult,
				&listenerUUID,
				&implantUUID,
				&success,
				&taskDate,
				&taskStatus,
				)
			if err != nil {
				return task, err
			}
			boolSuccess, err := strconv.ParseBool(success)
			if err != nil {
				return task, err
			}
			task = messages.Task{
				Type:         taskType,
				UUID:         uuid.Must(uuid.FromString(resultTaskUUID)),
				Args:         strings.Split(arguments, " "),
				Result:       taskResult,
				ListenerUUID: uuid.Must(uuid.FromString(listenerUUID)),
				ImplantUUID:  uuid.Must(uuid.FromString(implantUUID)),
				Success:      boolSuccess,
				Date:         taskDate,
			}
			return task, nil
			}
		}
	return task, errors.New("There is not task " + taskUUID.String())

}

// Function to retrieve a task for a listener on the DB
func (dao *DAO) GetTaskForListener(listenerUUID uuid.UUID) (messages.Task, error) {
	var task messages.Task

	db, err := sql.Open("sqlite3", dao.DBPath)
	if err != nil {
		return task, err
	}
	defer db.Close()
	statement, err := db.Prepare("SELECT uuid, type, arguments, listener_uuid, implant_uuid FROM tasks WHERE listener_uuid=? AND status='created' LIMIT 1;")
	if err != nil {
		return task, nil
	}
	defer statement.Close()
	rows, err := statement.Query(listenerUUID.String())
	if err != nil {
		return task, nil
	}
	defer rows.Close()
	var taskUUID, taskType, taskArgs, taskLUUID, taskIUUID string
	if rows != nil {
		for rows.Next(){
			err := rows.Scan(
				&taskUUID,
				&taskType,
				&taskArgs,
				&taskLUUID,
				&taskIUUID,
			)
			if err != nil {
				return task, err
			}
		}
		if taskType != "" {
			task := messages.Task{
				Type:         taskType,
				UUID:         uuid.Must(uuid.FromString(taskUUID)),
				Args:         strings.Split(taskArgs, " "),
				ListenerUUID: uuid.Must(uuid.FromString(taskLUUID)),
				ImplantUUID:  uuid.Must(uuid.FromString(taskIUUID)),
			}
			// Set the task to be in progress
			updateStatement, err := db.Prepare("UPDATE tasks SET status='in_progress' WHERE uuid=?;")
			if err != nil {
				return task, err
			}
			result, err := updateStatement.Exec(task.UUID.String())
			if err != nil {
				return task, err
			}
			affected, err := result.RowsAffected()
			if err != nil {
				return task, err
			}
			if affected != 1 {
				return task, errors.New("error while updating task status")
			}
			return task, nil
		}
	}
	// No task and no error
	return task, nil
}

// Method to delete a listener from the DB
func (dao *DAO) DeleteListener(listenerUUID string) error {

	db, err := sql.Open("sqlite3", dao.DBPath)
	if err != nil {
		return err
	}
	defer db.Close()
	// Create statement
	statement, err := db.Prepare("DELETE FROM listeners WHERE uuid=?;")
	if err != nil {
		return err
	}
	defer statement.Close()
	// Exec statement
	deleteResult, err := statement.Exec(listenerUUID)
	if err != nil {
		return err
	}

	rows, err := deleteResult.RowsAffected()
	if err != nil {
		return err
	}

	if rows != 1 {
		return errors.New("Failed to delete the listener")
	}
	return nil
}

// Method to delete an implant from the DB
func (dao *DAO) DeleteImplant(implantUUID string) error {
	db, err := sql.Open("sqlite3", dao.DBPath)
	if err != nil {
		return err
	}
	defer db.Close()
	statement, err := db.Prepare("UPDATE implants SET status='Not active' WHERE uuid=?;")
	if err != nil {
		return err
	}
	defer statement.Close()
	result, err := statement.Exec(implantUUID)
	if err != nil {
		return err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected != 1 {
		return errors.New("Could not delete the implant " + implantUUID)
	}
	return nil
}

// Method to update implants options
func (dao *DAO) UpdateImplantDetails(option, value string, implantUUID string) error {
	db, err := sql.Open("sqlite3", dao.DBPath)
	if err != nil {
		return err
	}
	defer db.Close()
	var optionParsed string
	switch option {
	case "Sleep": optionParsed = "sleep_time"
	case "Jitter": optionParsed = strings.ToLower(option)
	case "KillDate": optionParsed = "kill_date"
	}

	statement, err := db.Prepare("UPDATE implants SET " + optionParsed + "=? WHERE uuid=?;")
	if err != nil {
		return err
	}
	defer statement.Close()
	result, err := statement.Exec(value, implantUUID)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return errors.New("failed to update " + implantUUID + " details")
	}
	return nil
}

// Method to update the task result
func (dao *DAO) UpdateTaskResult(task messages.Task) error {
	db, err := sql.Open("sqlite3", dao.DBPath)
	if err != nil {
		return err
	}
	defer db.Close()
	statement, err := db.Prepare("UPDATE tasks SET result=?, success=?, date=?, status='completed' WHERE uuid=?;")
	if err != nil {
		return err
	}
	defer statement.Close()
	result, err := statement.Exec(task.Result, strconv.FormatBool(task.Success), task.Date, task.UUID.String())
	if err != nil {
		return err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected != 1 {
		return errors.New("failed to update task")
	}
	return nil
}