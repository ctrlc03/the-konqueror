package syscalls

import (
	"golang.org/x/sys/windows"
	"syscall"
	"unsafe"
)

// Do the interface allocations only once for common
// Errno values.
const (
	errnoERROR_IO_PENDING = 997
)

var (
	errERROR_IO_PENDING error = syscall.Errno(errnoERROR_IO_PENDING)
)

// Import DLL and functions
var (
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procVirtualAllocEx 		  = kernel32.NewProc("VirtualAllocEx")
	procWriteProcessMemory    = kernel32.NewProc("WriteProcessMemory")
	procVirtualProtectEx      = kernel32.NewProc("VirtualProtectEx")
	procCreateRemoteThread    = kernel32.NewProc("CreateRemoteThread")
	procGetExitCodeThread     = kernel32.NewProc("GetExitCodeThread")
)

// errnoErr returns common boxed Errno values, to prevent
// allocations at runtime.
func errnoErr(e syscall.Errno) error {
	switch e {
	case 0:
		return nil
	case errnoERROR_IO_PENDING:
		return errERROR_IO_PENDING
	}

	return e
}


func VirtualAllocEx(hProcess windows.Handle, lpAddress uintptr, dwSize uintptr, flAllocationType uint32, flProtect uint32) (addr uintptr, err error) {
	r0, _, e1 := syscall.Syscall6(procVirtualAllocEx.Addr(), 5, uintptr(hProcess), uintptr(lpAddress), uintptr(dwSize), uintptr(flAllocationType), uintptr(flProtect), 0)
	addr = uintptr(r0)
	if addr == 0 {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func WriteProcessMemory(hProcess windows.Handle, lpBaseAddress uintptr, lpBuffer *byte, nSize uintptr, lpNumberOfBytesWritten *uintptr) (err error) {
	r1, _, e1 := syscall.Syscall6(procWriteProcessMemory.Addr(), 5, uintptr(hProcess), uintptr(lpBaseAddress), uintptr(unsafe.Pointer(lpBuffer)), uintptr(nSize), uintptr(unsafe.Pointer(lpNumberOfBytesWritten)), 0)
	if r1 == 0 {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func CreateRemoteThread(hProcess windows.Handle, lpThreadAttributes *windows.SecurityAttributes, dwStackSize uint32, lpStartAddress uintptr, lpParameter uintptr, dwCreationFlags uint32, lpThreadId *uint32) (threadHandle windows.Handle, err error) {
	r0, _, e1 := syscall.Syscall9(procCreateRemoteThread.Addr(), 7, uintptr(hProcess), uintptr(unsafe.Pointer(lpThreadAttributes)), uintptr(dwStackSize), uintptr(lpStartAddress), uintptr(lpParameter), uintptr(dwCreationFlags), uintptr(unsafe.Pointer(lpThreadId)), 0, 0)
	threadHandle = windows.Handle(r0)
	if threadHandle == 0 {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func VirtualProtectEx(hProcess windows.Handle, lpAddress uintptr, dwSize uintptr, flNewProtect uint32, lpflOldProtect *uint32) (err error) {
	r1, _, e1 := syscall.Syscall6(procVirtualProtectEx.Addr(), 5, uintptr(hProcess), uintptr(lpAddress), uintptr(dwSize), uintptr(flNewProtect), uintptr(unsafe.Pointer(lpflOldProtect)), 0)
	if r1 == 0 {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func GetExitCodeThread(hTread windows.Handle, lpExitCode *uint32) (err error) {
	r1, _, e1 := syscall.Syscall(procGetExitCodeThread.Addr(), 2, uintptr(hTread), uintptr(unsafe.Pointer(lpExitCode)), 0)
	if r1 == 0 {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

