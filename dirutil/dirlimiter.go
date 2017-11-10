package dirutil

import (
	"path/filepath"
	"os"
	"errors"
	"strings"
	"sync"
	"fmt"
)

type Path struct {
	In  string
	Out string
}

var whitelistExt = map[string]bool{
	".php":    true,
	".htm":    true,
	".js":     true,
	".css":    true,
	".html":   true,
	".txt":    true,
	".xml":    true,
	".json":   true,
	".config": true,
	".ini":    true,
	".conf":   true,
	".md5":    true,
	".inc":    true,
	".csv":    true,
	".md":     true,
}

// Recursively read files in a directory
// and output files string which is accepted or rejected according with different whitelist and blacklist
func WalkService(done <-chan struct{}, inDirPath string, outDirPath string, extensionWhitelist bool, blacklistMap map[string]bool, skipDirListMap map[string]bool) (<-chan Path, <-chan Path, <-chan error) {
	paths := make(chan Path)
	rejectedPaths := make(chan Path)
	errc := make(chan error, 1)
	go func() {
		defer close(paths)
		defer close(rejectedPaths)
		// No select needed for this send, since errc is buffered.
		errc <- filepath.Walk(inDirPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			var retPath Path

			// skip hidden file and directory
			if filepath.Base(path)[0] == '.' {
				if info.Mode().IsDir() {
					return filepath.SkipDir
				}
				return nil
			}

			// skip directory in the list
			if len(skipDirListMap) != 0 {
				if _, ok := skipDirListMap[path]; ok {
					return filepath.SkipDir
				}
			}

			outpath := evaluateOutputPath(outDirPath, path)
			retPath.In = path
			retPath.Out = outpath

			// cannot return as a service for worker to create.
			// because the order is very matter
			// create directory
			if info.Mode().IsDir() {
				fmt.Println("Creating directory", outpath)
				os.MkdirAll(outpath, os.ModePerm)
				return nil
			}

			// only accept file which has the extension in the whitelist
			if extensionWhitelist {
				// hardcoded suffix whitelist. Reason: hard to pass array as cli args
				ext := filepath.Ext(filepath.Base(path))
				if _, ok := whitelistExt[ext]; !ok {
					select {
					case rejectedPaths <- retPath:
					case <-done:
						return errors.New("walk canceled")
					}
					return nil
				}
			}

			// reject file in the black list
			if len(blacklistMap) != 0 {
				if _, ok := blacklistMap[path]; ok {
					select {
					case rejectedPaths <- retPath:
					case <-done:
						return errors.New("walk canceled")
					}
					return nil
				}
			}

			// These path are accepted
			select {
			case paths <- retPath:
			case <-done:
				return errors.New("walk canceled")
			}
			return nil
		})
	}()
	return paths, rejectedPaths, errc
}

func WorkerGroup(numWorkers int, handler func()) {
	var wg sync.WaitGroup

	wg.Add(numWorkers)
	for i := 0; i < numWorkers; i++ {
		go func() {
			defer wg.Done()
			handler()
		}()
	}
	wg.Wait()
}

// e.g.
// inDirPath = "test", outDirPath = "test_utf8",
// input: file1 = "test/abc.txt", file2 = "test/def.txt", file3 = "test/sub/sub_abc.txt"
// output: "test_utf8/abc.txt", "test_utf8/def.txt", "test_utf8/sub/sub_abc.txt"
func evaluateOutputPath(outdir string, inpath string) string {
	pathSlice := strings.Split(inpath, string(os.PathSeparator))
	pathSlice[0] = outdir
	return strings.Join(pathSlice, string(os.PathSeparator))
}
