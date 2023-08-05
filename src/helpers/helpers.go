package helpers

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"github.com/chzyer/readline"
	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
	uuid "github.com/satori/go.uuid"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"

	"../messages"
)

// Time layout to be consistent throughout the program
const _timeLayout = "2006-01-02 15:04:05"

// This function prints the time in a nice way
func PrintTime() string {
	return "[" + time.Now().Format(_timeLayout) + "] "
}

// Helper function to print nicely
func NicePrinting(messageType string, message string) {
	switch messageType {
	case "info":
		color.Green("[i]%s ", PrintTime() + message)
	case "plus":
		color.Cyan("[+]%s ", PrintTime() + message)
	case "fail":
		color.Red("[-]%s ", PrintTime()+message)
	case "important":
		color.White("[!]%s ", PrintTime()+message)
	}
}

// Help for the implants menu
func ImplantsHelpMenu() {
	data := [][]string{
		{"help", "Display this menu"},
		{"?", "Display this menu"},
		{"main", "Go to the main menu"},
		{"back", "Go to the main menu"},
		{"get", "Get task taskUUID to get a task result"},
		{"ls", "List files on the target machine"},
		{"cmd", "Execute a cmd either via cmd.exe or bash"},
		{"powershell", "Execute a cmd via PowerShell"},
		{"set", "Change a setting on the implant"},
		{"info", "Print the implant info"},
		{"sysinfo", "Print the target machine info"},
		{"upload", "Upload a file to the target machine"},
		{"download", "Download a file from the target machine"},
		{"ps", "List running processes"},
		{"ifconfig", "List network interfaces"},
		{"execute-assembly", "Execute a .NET assembly from memory. execute-assembly path_to_hosting_clr path_to_net_assembly process_to_spawn arguments"},
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Command", "Description"})

	for _, v := range data {
		table.Append(v)
	}

	table.Render()
}

// Help for the listeners menu
func ListenersHelpMenu() {
	data := [][]string{
		{"help", "Display this menu"},
		{"?", "Display this menu"},
		{"main", "Go to the main menu"},
		{"back", "Go to the main menu"},
		{"generate", "Generate a new listener, syntax = generate listenertype AESKey HMACKey"},
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Command", "Description"})

	for _, v := range data {
		table.Append(v)
	}

	table.Render()
}

// Help for the main menu
func MainHelpMenu() {

	data := [][]string{
		{"help", "Display this menu"},
		{"?", "Display this menu"},
		{"interact", "Go to the implants menu (can autocomplete implant name)"},
		{"listeners", "Go to the listeners menu"},
		{"list listeners", "List active listeners"},
		{"list implants", "List active agents"},
		{"kill implant", "Kill an implant, will need the name"},
		{"kill listener", "Kill a listener, will need the listener name - automatically kills the implant"},
		{"set listener", "Set a listener to use by UUID"},
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Command", "Description"})

	for _, v := range data {
		table.Append(v)
	}

	table.Render()
}

// From https://github.com/chzyer/readline/blob/master/example/readline-demo/readline-demo.go
func FilterInput(r rune) (rune, bool) {
	switch r {
	// block CtrlZ feature
	case readline.CharCtrlZ:
		return r, false
	}
	return r, true
}

// This function is called when there is an error which leads to the application closing
func ExitOnError(errorMessage string) {
	NicePrinting("fail", errorMessage)
	NicePrinting("info", "Exiting...")
	os.Exit(1)
}

// This function prints the server banner
func ServerBanner() {

	banner := `

				___________.__            
				\__    ___/|  |__   ____  
				  |    |   |  |  \_/ __ \ 
				  |    |   |   Y  \  ___/ 
				  |____|   |___|  /\___  >
						\/     \/
		 ____  __.                                                     
		|    |/ _|____   ____   ________ __   ___________  ___________ 
		|      < /  _ \ /    \ / ____/  |  \_/ __ \_  __ \/  _ \_  __ \
		|    |  (  <_> )   |  < <_|  |  |  /\  ___/|  | \(  <_> )  | \/
		|____|__ \____/|___|  /\__   |____/  \___  >__|   \____/|__|   
			\/          \/    |__|           \/                    
			  _________                                
			 /   _____/ ______________  __ ___________ 
			 \_____  \_/ __ \_  __ \  \/ // __ \_  __ \
			 /        \  ___/|  | \/\   /\  ___/|  | \/
			/_______  /\___  >__|    \_/  \___  >__|   
				\/     \/                 \/

							[v0.1.0 by ctrlc03]
`
	color.Red(banner + "\n\n")

}

// This function prints the client banner
func ClientBanner() {

	banner := `

				___________.__            
				\__    ___/|  |__   ____  
				  |    |   |  |  \_/ __ \ 
				  |    |   |   Y  \  ___/ 
				  |____|   |___|  /\___  >
						\/     \/
		 ____  __.                                                     
		|    |/ _|____   ____   ________ __   ___________  ___________ 
		|      < /  _ \ /    \ / ____/  |  \_/ __ \_  __ \/  _ \_  __ \
		|    |  (  <_> )   |  < <_|  |  |  /\  ___/|  | \(  <_> )  | \/
		|____|__ \____/|___|  /\__   |____/  \___  >__|   \____/|__|   
			\/    	    \/    |__|           \/                    

			_________ .__  .__               __   
			\_   ___ \|  | |__| ____   _____/  |_ 
			/    \  \/|  | |  |/ __ \ /    \   __\
			\     \___|  |_|  \  ___/|   |  \  |  
			 \______  /____/__|\___  >___|  /__|  
				\/             \/     \/      

						[v0.1.0 by ctrlc03]
`

	color.Red(banner + "\n\n")
}

// This function checks if an implant is inside an implant slice by UUID
func ImplantInImplantsSlice(implantID uuid.UUID, implants []*messages.Implant) bool{
	for _, implant := range implants{
		if implantID == implant.UUID{
			return true
		}
	}
	return false
}

// Function to get index of implant from a slice
func GetImplantIndexFromSlice (implantUUID uuid.UUID, implantSlice []*messages.Implant) int {
	for index, implant := range implantSlice {
		if implant.UUID == implantUUID {
			return index
		}
	}
	return -1
}

// Function to check if a file exists
func CheckFile(filePath string) bool {
	if _, err := os.Stat(filePath); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

// Get Export Offset utils

// ExportDirectory - stores the Export data
type ExportDirectory struct {
	Characteristics       uint32
	TimeDateStamp         uint32
	MajorVersion          uint16
	MinorVersion          uint16
	Name                  uint32
	Base                  uint32
	NumberOfFunctions     uint32
	NumberOfNames         uint32
	AddressOfFunctions    uint32 // RVA from base of image
	AddressOfNames        uint32 // RVA from base of image
	AddressOfNameOrdinals uint32 // RVA from base of image
}

func rvaToFoa(rva uint32, pefile *pe.File) uint32 {
	var offset uint32
	for _, section := range pefile.Sections {
		if rva >= section.SectionHeader.VirtualAddress && rva <= section.SectionHeader.VirtualAddress+section.SectionHeader.Size {
			offset = section.SectionHeader.Offset + (rva - section.SectionHeader.VirtualAddress)
		}
	}
	return offset
}

func getFuncName(index uint32, rawData []byte, fpe *pe.File) string {
	nameRva := binary.LittleEndian.Uint32(rawData[index:])
	nameFOA := rvaToFoa(nameRva, fpe)
	funcNameBytes, err := bytes.NewBuffer(rawData[nameFOA:]).ReadBytes(0)
	if err != nil {
		log.Fatal(err)
		return ""
	}
	funcName := string(funcNameBytes[:len(funcNameBytes)-1])
	return funcName
}

func getOrdinal(index uint32, rawData []byte, fpe *pe.File, funcArrayFoa uint32) uint32 {
	ordRva := binary.LittleEndian.Uint16(rawData[index:])
	funcArrayIndex := funcArrayFoa + uint32(ordRva)*8
	funcRVA := binary.LittleEndian.Uint32(rawData[funcArrayIndex:])
	funcOffset := rvaToFoa(funcRVA, fpe)
	return funcOffset
}

// Function used by the client to get the offset of the CLR's exported function (ReflectiveLoader)
func GetExportOffset(filepath string, exportName string) (funcOffset uint32, err error) {
	rawData, err := ioutil.ReadFile(filepath)
	if err != nil {
		return 0, err
	}
	handle, err := os.Open(filepath)
	if err != nil {
		return 0, err
	}
	defer handle.Close()
	fpe, _ := pe.NewFile(handle)
	exportDirectoryRVA := fpe.OptionalHeader.(*pe.OptionalHeader64).DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
	var offset = rvaToFoa(exportDirectoryRVA, fpe)
	exportDir := ExportDirectory{}
	buff := &bytes.Buffer{}
	buff.Write(rawData[offset:])
	err = binary.Read(buff, binary.LittleEndian, &exportDir)
	if err != nil {
		return 0, err
	}
	current := exportDir.AddressOfNames
	nameArrayFOA := rvaToFoa(exportDir.AddressOfNames, fpe)
	ordinalArrayFOA := rvaToFoa(exportDir.AddressOfNameOrdinals, fpe)
	funcArrayFoa := rvaToFoa(exportDir.AddressOfFunctions, fpe)

	for i := uint32(0); i < exportDir.NumberOfNames; i++ {
		index := nameArrayFOA + i*8
		name := getFuncName(index, rawData, fpe)
		if strings.Contains(name, exportName) {
			ordIndex := ordinalArrayFOA + i*2
			funcOffset = getOrdinal(ordIndex, rawData, fpe, funcArrayFoa)
		}
		current += uint32(binary.Size(i))
	}

	return
}

// PE

type(
	DWORD           uint32
)

const (
	IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16
	IMAGE_FILE_MACHINE_I386          = 0x014c
	IMAGE_FILE_MACHINE_AMD64         = 0x8664
	DLL_PROCESS_ATTACH               = 1
	DLL_THREAD_ATTACH                = 2
	DLL_THREAD_DETACH                = 3
	DLL_PROCESS_DETACH               = 0

	IMAGE_DIRECTORY_ENTRY_EXPORT         = 0  // Export Directory
	IMAGE_DIRECTORY_ENTRY_IMPORT         = 1  // Import Directory
	IMAGE_DIRECTORY_ENTRY_RESOURCE       = 2  // Resource Directory
	IMAGE_DIRECTORY_ENTRY_EXCEPTION      = 3  // Exception Directory
	IMAGE_DIRECTORY_ENTRY_SECURITY       = 4  // Security Directory
	IMAGE_DIRECTORY_ENTRY_BASERELOC      = 5  // Base Relocation Table
	IMAGE_DIRECTORY_ENTRY_DEBUG          = 6  // Debug Directory
	IMAGE_DIRECTORY_ENTRY_ARCHITECTURE   = 7  // Architecture Specific Data
	IMAGE_DIRECTORY_ENTRY_GLOBALPTR      = 8  // RVA of GP
	IMAGE_DIRECTORY_ENTRY_TLS            = 9  // TLS Directory
	IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    = 10 // Load Configuration Directory
	IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   = 11 // Bound Import Directory in headers
	IMAGE_DIRECTORY_ENTRY_IAT            = 12 // Import Address Table
	IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   = 13 // Delay Load Import Descriptors
	IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14 // COM Runtime descriptor
	IMAGE_REL_BASED_HIGHLOW              = 3
	IMAGE_REL_BASED_DIR64                = 10
	IMAGE_ORDINAL_FLAG64                 = 0x8000000000000000
	IMAGE_ORDINAL_FLAG32                 = 0x80000000
)

type ULONGLONG uint64

type LONG uint32
type WORD uint16
type BOOL uint8
type BYTE uint8

type IMAGE_BASE_RELOCATION struct {
	VirtualAddress DWORD
	SizeOfBlock    DWORD
	//  WORD    TypeOffset[1];
}

type IMAGE_IMPORT_BY_NAME struct {
	Hint WORD
	Name [1]uint8
}

type IMAGE_IMPORT_DESCRIPTOR struct {
	/*
		union {
		DWORD   Characteristics;            // 0 for terminating null import descriptor
		DWORD   OriginalFirstThunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
		} DUMMYUNIONNAME;
		DWORD   TimeDateStamp;                  // 0 if not bound,
		// -1 if bound, and real date\time stamp
		//     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
		// O.W. date/time stamp of DLL bound to (Old BIND)

		DWORD   ForwarderChain;                 // -1 if no forwarders
		DWORD   Name;
		DWORD   FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses)

	*/
	OriginalFirstThunk DWORD
	TimeDateStamp      DWORD
	ForwarderChain     DWORD
	Name               DWORD
	FirstThunk         DWORD
}

type _IMAGE_NT_HEADERS64 struct {
	Signature      DWORD
	FileHeader     IMAGE_FILE_HEADER
	OptionalHeader IMAGE_OPTIONAL_HEADER
}
type IMAGE_NT_HEADERS64 _IMAGE_NT_HEADERS64
type IMAGE_NT_HEADERS IMAGE_NT_HEADERS64

type _IMAGE_DATA_DIRECTORY struct {
	VirtualAddress DWORD
	Size           DWORD
}
type IMAGE_DATA_DIRECTORY _IMAGE_DATA_DIRECTORY

type _IMAGE_OPTIONAL_HEADER64 struct {
	Magic                       WORD
	MajorLinkerVersion          BYTE
	MinorLinkerVersion          BYTE
	SizeOfCode                  DWORD
	SizeOfInitializedData       DWORD
	SizeOfUninitializedData     DWORD
	AddressOfEntryPoint         DWORD
	BaseOfCode                  DWORD
	ImageBase                   ULONGLONG
	SectionAlignment            DWORD
	FileAlignment               DWORD
	MajorOperatingSystemVersion WORD
	MinorOperatingSystemVersion WORD
	MajorImageVersion           WORD
	MinorImageVersion           WORD
	MajorSubsystemVersion       WORD
	MinorSubsystemVersion       WORD
	Win32VersionValue           DWORD
	SizeOfImage                 DWORD
	SizeOfHeaders               DWORD
	CheckSum                    DWORD
	Subsystem                   WORD
	DllCharacteristics          WORD
	SizeOfStackReserve          ULONGLONG
	SizeOfStackCommit           ULONGLONG
	SizeOfHeapReserve           ULONGLONG
	SizeOfHeapCommit            ULONGLONG
	LoaderFlags                 DWORD
	NumberOfRvaAndSizes         DWORD
	DataDirectory               [IMAGE_NUMBEROF_DIRECTORY_ENTRIES]IMAGE_DATA_DIRECTORY
}

type IMAGE_OPTIONAL_HEADER64 _IMAGE_OPTIONAL_HEADER64
type IMAGE_OPTIONAL_HEADER IMAGE_OPTIONAL_HEADER64

type _IMAGE_FILE_HEADER struct {
	Machine              WORD
	NumberOfSections     WORD
	TimeDateStamp        DWORD
	PointerToSymbolTable DWORD
	NumberOfSymbols      DWORD
	SizeOfOptionalHeader WORD
	Characteristics      WORD
}

type IMAGE_FILE_HEADER _IMAGE_FILE_HEADER

type _IMAGE_DOS_HEADER struct { // DOS .EXE header
	E_magic    WORD     // Magic number
	E_cblp     WORD     // Bytes on last page of file
	E_cp       WORD     // Pages in file
	E_crlc     WORD     // Relocations
	E_cparhdr  WORD     // Size of header in paragraphs
	E_minalloc WORD     // Minimum extra paragraphs needed
	E_maxalloc WORD     // Maximum extra paragraphs needed
	E_ss       WORD     // Initial (relative) SS value
	E_sp       WORD     // Initial SP value
	E_csum     WORD     // Checksum
	E_ip       WORD     // Initial IP value
	E_cs       WORD     // Initial (relative) CS value
	E_lfarlc   WORD     // File address of relocation table
	E_ovno     WORD     // Overlay number
	E_res      [4]WORD  // Reserved words
	E_oemid    WORD     // OEM identifier (for E_oeminfo)
	E_oeminfo  WORD     // OEM information; E_oemid specific
	E_res2     [10]WORD // Reserved words
	E_lfanew   LONG     // File address of new exe header
}

type IMAGE_DOS_HEADER _IMAGE_DOS_HEADER

const (
	IMAGE_SIZEOF_SHORT_NAME = 8
)

type _IMAGE_SECTION_HEADER struct {
	Name [IMAGE_SIZEOF_SHORT_NAME]BYTE
	//union {
	//DWORD   PhysicalAddress;
	//DWORD   VirtualSize;
	//} Misc;
	Misc                 DWORD
	VirtualAddress       DWORD
	SizeOfRawData        DWORD
	PointerToRawData     DWORD
	PointerToRelocations DWORD
	PointerToLinenumbers DWORD
	NumberOfRelocations  WORD
	NumberOfLinenumbers  WORD
	Characteristics      DWORD
}

type IMAGE_SECTION_HEADER _IMAGE_SECTION_HEADER

type IMAGE_EXPORT_DIRECTORY struct {
	Characteristics       DWORD
	TimeDateStamp         DWORD
	MajorVersionv         WORD
	MinorVersion          WORD
	Name                  DWORD
	Base                  DWORD
	NumberOfFunctions     DWORD
	NumberOfNames         DWORD
	AddressOfFunctions    DWORD // RVA from base of image
	AddressOfNames        DWORD // RVA from base of image
	AddressOfNameOrdinals DWORD // RVA from base of image
}