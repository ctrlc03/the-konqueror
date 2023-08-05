# Build

Here you can find the utility to create implants from a template file. 

# Instructions

`go run create_implant.go`

You will need to specify:

* Path to the configuration file (../config/implant_template.json)
* Path to the implant template source (implant_template.go)
* The name of the implant source which will be generated

Once this is completed, you can build the implant for your favourite target architecture with the following command:

`GOOS=os GOARCH=architecture go build -o name_of_binary implant_name.go` 

Example:

`GOOS=windows GOARCH=amd64 go build -o windows_x64_implant.exe implant_name.go`
