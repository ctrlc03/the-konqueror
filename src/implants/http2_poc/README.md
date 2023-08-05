# HTTP/2 Implant 

Source code for the HTTP/2 PoC implant. The template file which can be used to produce a working implant can be found in the **/src/build** directory instead.

## Functionalities

The following functionalities are available with this release of the Implant:

* **sysinfo** - Get info about the target system
* **info**  - Get info about the Implant
* **upload** - Upload a file to the target system:
  * `upload local_file_path remote_file_path`
* **download** - Download a file from the target system:
  * `download remote_file_path local_file_path`
* **ls** - List remote files:
  * `ls dir` - If no directory is provided then it will list the current directory content
* **cat** - Cat a file:
  * `cat remote_file_path`
* **ifconfig** - List network interfaces
* **cmd** - Execute a shell command (Bash or Cmd.exe depending on the system):
  * `cmd command args`
* **powershell** - Execute a PowerShell command (Will only work on Windows systems):
  * `powershell command args`
* **set** - Change an option of the Implant:
  * `set option value`
* **ps** - List all running processes
* **execute-assembly** - Execute a .NET assembly from memory:
    * `execute-assembly path_to_hosting_clr path_to_assembly process_to_create arguments_to_assembly`