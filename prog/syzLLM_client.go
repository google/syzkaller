package prog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

// 1. parse syscall sequence from prog to list
// 2. add "MASK" to the list
// 3. send the JSON to server
// 4. wait the result {state_num, syscall}

type ServerConfig struct {
	Port     int
	Host     string
	HostName string
}

func getServerConfig() ServerConfig {
	var parallel = ServerConfig{
		Port:     0000,
		Host:     "xxxx",
		HostName: "MAC",
	}

	return parallel
}

func (ctx *mutator) requestMaskSyscall(prog Prog, insertPosition int) {
	//call := prog.Calls[0]

	// Create a sample list to send as JSON
	syscallList := []string{"apple", "banana", "cherry"}

	// Convert the list to JSON
	jsonData, err := json.Marshal(syscallList)
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		return
	}

	var serviceConfig = getServerConfig()
	// Send the JSON data to the specified IP and port
	url := fmt.Sprintf("http://%s:%s", serviceConfig.Host, serviceConfig.Port)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Println("Error sending JSON:", err)
		return
	}
	defer resp.Body.Close()

	// Read the response from the server
	responseData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response:", err)
		return
	}

	// Convert the response JSON to a list
	var responseList []string
	err = json.Unmarshal(responseData, &responseList)
	if err != nil {
		fmt.Println("Error unmarshaling response:", err)
		return
	}

	// Print the received list
	fmt.Println("Received list:", responseList)
}
