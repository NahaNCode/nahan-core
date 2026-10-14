package update

import (
	"os"
	"runtime"
	"sync"
)

var runningOnce sync.Once
var runningDigest string

func RunningDigest() string {
	runningOnce.Do(func() {
		path, err := os.Executable()
		if err != nil {
			return
		}
		if runtime.GOOS == "linux" {
			path = "/proc/self/exe"
		}
		runningDigest, _ = Hash(path)
	})
	return runningDigest
}
func Available(core string) bool {
	if !UUIDPattern.MatchString(core) {
		return false
	}
	info, err := os.Lstat(Socket(core))
	return err == nil && info.Mode()&os.ModeSocket != 0
}
