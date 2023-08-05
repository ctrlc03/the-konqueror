package ps

// Taken from https://raw.githubusercontent.com/mitchellh/go-ps
/*
The MIT License (MIT)
Copyright (c) 2014 Mitchell Hashimoto
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

*/

// Process is the generic interface that is implemented on every platform
// and provides common operations for processes.
type Process interface {
	// Pid is the process ID for this process.
	Pid() int

	// PPid is the parent process ID for this process.
	PPid() int

	// Executable name running this process. This is not a path to the
	// executable.
	Executable() string

	// The process owner
	Owner() string
}

// Processes returns all processes.
//
// This of course will be a point-in-time snapshot of when this method was
// called. Some operating systems don't provide snapshot capability of the
// process table, in which case the process table returned might contain
// ephemeral entities that happened to be running when this was called.
func Processes() ([]Process, error) {
	return processes()
}

// FindProcess looks up a single process by pid.
//
// Process will be nil and error will be nil if a matching process is
// not found.
func FindProcess(pid int) (Process, error) {
	return findProcess(pid)
}