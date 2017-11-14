package main

import (
	"os"
	"bufio"
	"fmt"
	"golang.org/x/text/encoding/traditionalchinese"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/encoding/korean"
	"golang.org/x/text/encoding/japanese"
	"golang.org/x/text/encoding"
	"golang.org/x/text/transform"
	"time"
	"flag"
	"runtime"

	"path/filepath"
	"strings"
	"io"
	"my/big5ToUTF8_2/dirutil"
	"sync"
	"errors"
	"my/big5ToUTF8_2/customhtml"
	"github.com/saintfish/chardet"
	"io/ioutil"
	"encoding/json"
)

var inPath string
var outPath string

var dir bool

var rbuf int
var wbuf int

var unstr bool
var workerPool int

var from string

var extensionWhitelist bool
var blacklistPath string
var skipDirListPath string
var fromlistPath string

// For bufio.Scanner, if scanner read one line each time, if the line is too long, it will throw error.
// Pitfall: While processing cdb_posts, it reports the line is too long.
const startBufSize = 4096
var maxScanTokenSize int

var chongMaList = [240]string{
	"䪤" /* 0x875C */, "𣚞" /* 0x877C */, "Ě" /* 0x885C */, "ǖ" /* 0x887C */, "声" /* 0x895C */,
	"车" /* 0x897C */, "蹾" /* 0x8A5C */, "𡁷" /* 0x8A7C */, "胬" /* 0x8B5C */, "𡃶" /* 0x8B7C */,
	"𨜏" /* 0x8C5C */, "忂" /* 0x8C7C */, "㙡" /* 0x8D5C */, "挘" /* 0x8D7C */, "笋" /* 0x8E5C */,
	"糳" /* 0x8E7C */, "蕚" /* 0x8F5C */, "䔖" /* 0x8F7C */, "𪀔" /* 0x905C */, "𣲛" /* 0x907C */,
	"髢" /* 0x915C */, "𪄴" /* 0x917C */, "𦰡" /* 0x925C */, "諚" /* 0x927C */, "脪" /* 0x935C */,
	"𢴇" /* 0x937C */, "𠗫" /* 0x945C */, "𤦫" /* 0x947C */, "𦖭" /* 0x955C */, "蠭" /* 0x957C */,
	"䓀" /* 0x965C */, "𡌂" /* 0x967C */, "珢" /* 0x975C */, "䤵" /* 0x977C */, "娫" /* 0x985C */,
	"𡟟" /* 0x987C */, "糭" /* 0x995C */, "腖" /* 0x997C */, "䨵" /* 0x9A5C */, "𡯂" /* 0x9A7C */,
	"鞸" /* 0x9B5C */, "𠍆" /* 0x9B7C */, "㘘" /* 0x9C5C */, "补" /* 0x9C7C */, "𩄼" /* 0x9D5C */,
	"𠲜" /* 0x9D7C */, "疱" /* 0x9E5C */, "𧿹" /* 0x9E7C */, "髿" /* 0x9F5C */, "鞺" /* 0x9F7C */,
	"癧" /* 0xA05C */, "捤" /* 0xA07C */, "﹏" /* 0xA15C */, "﹄" /* 0xA17C */, "兝" /* 0xA25C */,
	"└" /* 0xA27C */, "α" /* 0xA35C */, "ㄍ" /* 0xA37C */, "么" /* 0xA45C */, "弋" /* 0xA47C */,
	"功" /* 0xA55C */, "四" /* 0xA57C */, "吒" /* 0xA65C */, "帆" /* 0xA67C */, "吭" /* 0xA75C */,
	"坑" /* 0xA77C */, "沔" /* 0xA85C */, "育" /* 0xA87C */, "坼" /* 0xA95C */, "尚" /* 0xA97C */,
	"歿" /* 0xAA5C */, "泜" /* 0xAA7C */, "俞" /* 0xAB5C */, "咽" /* 0xAB7C */, "枯" /* 0xAC5C */,
	"洱" /* 0xAC7C */, "苒" /* 0xAD5C */, "迢" /* 0xAD7C */, "娉" /* 0xAE5C */, "徑" /* 0xAE7C */,
	"珮" /* 0xAF5C */, "砝" /* 0xAF7C */, "豹" /* 0xB05C */, "院" /* 0xB07C */, "崤" /* 0xB15C */,
	"悴" /* 0xB17C */, "淚" /* 0xB25C */, "琍" /* 0xB27C */, "許" /* 0xB35C */, "逖" /* 0xB37C */,
	"廄" /* 0xB45C */, "揉" /* 0xB47C */, "琵" /* 0xB55C */, "稅" /* 0xB57C */, "跚" /* 0xB65C */,
	"閏" /* 0xB67C */, "愧" /* 0xB75C */, "會" /* 0xB77C */, "稞" /* 0xB85C */, "腮" /* 0xB87C */,
	"鈾" /* 0xB95C */, "頌" /* 0xB97C */, "暝" /* 0xBA5C */, "漏" /* 0xBA7C */, "蓋" /* 0xBB5C */,
	"誡" /* 0xBB7C */, "墦" /* 0xBC5C */, "慝" /* 0xBC7C */, "穀" /* 0xBD5C */, "罵" /* 0xBD7C */,
	"閱" /* 0xBE5C */, "魯" /* 0xBE7C */, "璞" /* 0xBF5C */, "糕" /* 0xBF7C */, "餐" /* 0xC05C */,
	"嚐" /* 0xC07C */, "縷" /* 0xC15C */, "舉" /* 0xC17C */, "擺" /* 0xC25C */, "甕" /* 0xC27C */,
	"黠" /* 0xC35C */, "牘" /* 0xC37C */, "孀" /* 0xC45C */, "辮" /* 0xC47C */, "髏" /* 0xC55C */,
	"疊" /* 0xC57C */, "躡" /* 0xC65C */, "鸛" /* 0xC67C */, "ふ" /* 0xC75C */, "ア" /* 0xC77C */,
	"ж" /* 0xC85C */, "𠂊" /* 0xC87C */, "尐" /* 0xC95C */, "戉" /* 0xC97C */, "佢" /* 0xCA5C */,
	"吜" /* 0xCA7C */, "汻" /* 0xCB5C */, "芎" /* 0xCB7C */, "岤" /* 0xCC5C */, "怙" /* 0xCC7C */,
	"狖" /* 0xCD5C */, "矹" /* 0xCD7C */, "垥" /* 0xCE5C */, "峗" /* 0xCE7C */, "柦" /* 0xCF5C */,
	"洀" /* 0xCF7C */, "胐" /* 0xD05C */, "苶" /* 0xD07C */, "娖" /* 0xD15C */, "恝" /* 0xD17C */,
	"涂" /* 0xD25C */, "烡" /* 0xD27C */, "罡" /* 0xD35C */, "茦" /* 0xD37C */, "偅" /* 0xD45C */,
	"唰" /* 0xD47C */, "惝" /* 0xD55C */, "掤" /* 0xD57C */, "牾" /* 0xD65C */, "痎" /* 0xD67C */,
	"莍" /* 0xD75C */, "虖" /* 0xD77C */, "傜" /* 0xD85C */, "圌" /* 0xD87C */, "揊" /* 0xD95C */,
	"斮" /* 0xD97C */, "焮" /* 0xDA5C */, "琰" /* 0xDA7C */, "茻" /* 0xDB5C */, "萆" /* 0xDB7C */,
	"鄃" /* 0xDC5C */, "隇" /* 0xDC7C */, "幋" /* 0xDD5C */, "搉" /* 0xDD7C */, "滜" /* 0xDE5C */,
	"煟" /* 0xDE7C */, "綅" /* 0xDF5C */, "腶" /* 0xDF7C */, "赨" /* 0xE05C */, "輋" /* 0xE07C */,
	"塿" /* 0xE15C */, "嫟" /* 0xE17C */, "槙" /* 0xE25C */, "漒" /* 0xE27C */, "箤" /* 0xE35C */,
	"翣" /* 0xE37C */, "踊" /* 0xE45C */, "銔" /* 0xE47C */, "嫹" /* 0xE55C */, "憰" /* 0xE57C */,
	"潿" /* 0xE65C */, "獡" /* 0xE67C */, "蔌" /* 0xE75C */, "蔙" /* 0xE77C */, "醆" /* 0xE85C */,
	"鋧" /* 0xE87C */, "嬞" /* 0xE95C */, "懁" /* 0xE97C */, "獦" /* 0xEA5C */, "瞣" /* 0xEA7C */,
	"螏" /* 0xEB5C */, "褟" /* 0xEB7C */, "餤" /* 0xEC5C */, "鮐" /* 0xEC7C */, "燡" /* 0xED5C */,
	"瞲" /* 0xED7C */, "螰" /* 0xEE5C */, "觲" /* 0xEE7C */, "駹" /* 0xEF5C */, "鴱" /* 0xEF7C */,
	"礒" /* 0xF05C */, "聵" /* 0xF07C */, "鎪" /* 0xF15C */, "鞫" /* 0xF17C */, "瀙" /* 0xF25C */,
	"矱" /* 0xF27C */, "酀" /* 0xF35C */, "霬" /* 0xF37C */, "瀵" /* 0xF45C */, "礨" /* 0xF47C */,
	"騱" /* 0xF55C */, "鶘" /* 0xF57C */, "酅" /* 0xF65C */, "驂" /* 0xF67C */, "贕" /* 0xF75C */,
	"驏" /* 0xF77C */, "鱋" /* 0xF85C */, "鼶" /* 0xF87C */, "鱭" /* 0xF95C */, "鸓" /* 0xF97C */,
	"𣘀" /* 0xFA5C */, "𣲙" /* 0xFA7C */, "园" /* 0xFB5C */, "梦" /* 0xFB7C */, "𧃸" /* 0xFC5C */,
	"憇" /* 0xFC7C */, "檝" /* 0xFD5C */, "𤆤" /* 0xFD7C */, "𠰺" /* 0xFE5C */, "璂" /* 0xFE7C */,
}
var replaceChongMaSlash bool
var autoDetect bool

func init() {
	// program args flags
	flag.StringVar(&inPath, "in", "", "The input path of the big5 encoding file.")
	flag.StringVar(&outPath, "out", "", "The output path of the transformed utf8 encoding file")

	flag.StringVar(&from, "from", "big5", "The encoding transforming from")
	flag.BoolVar(&dir, "dir", false, "Use directory path")

	flag.IntVar(&rbuf, "rbuf", 1024*1024, "The reade buffer size. Default: 1MB")
	flag.IntVar(&wbuf, "wbuf", 512*1024, "The write buffer size. Default: 512KB")
	flag.IntVar(&maxScanTokenSize, "maxts", 128*1024*1024, "The maximum size of the line scanning. Default: 128MB")

	flag.BoolVar(&unstr, "unstr", false, "HTML unescapeString (&#xxxxx to character).")
	flag.IntVar(&workerPool, "wpool", 20, "The number of goroutine worker walk through the directory. i.e. The number of concurrency files progressing")

	flag.BoolVar(&extensionWhitelist, "extlist", false, "The extension whitelist. File extensions not in the below list will copy to target directory. For instance, [.png .gif]. hardcoded: [.php .htm .js .css .html .txt .xml .json .config .ini .conf .md5 .inc .csv .md]")
	flag.StringVar(&blacklistPath, "blacklist", "", "The file list that specifies which files should not apply transform and copy to target directory. For instance, utf8 files. Path should not start with '\\' Path separator is '/'. e.g. big5files/cdb_threads.txt")
	flag.StringVar(&skipDirListPath, "skipdirlist", "", "The file list of the skipping directory. The files in the skipped directory will not copy to target directory. Path should not start with '/' Path separator is '/'. e.g. forumdata")
	flag.StringVar(&fromlistPath, "fromlist", "", "The list specifies the decoder of different files.")
	flag.BoolVar(&replaceChongMaSlash, "chongMaSlash", false, "Remove slash after chong ma characters. e.g. from 許/ to 許")
	flag.BoolVar(&autoDetect, "autoDetect", false, "Auto Detect file encoding")
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	flag.Parse()

	// check args flags
	if dir {
		if inPath == "" {
			fmt.Println("Please specify the input directory path")
			fmt.Println()
			printUsage()
			return
		}
		if outPath == "" {
			outPath = inPath + "_utf8"
		}
	} else {
		if inPath == "" {
			fmt.Println("Please specify the input path.")
			fmt.Println()
			printUsage()
			return
		}
		if outPath == "" {
			dir, file := filepath.Split(inPath)
			fileArr := strings.Split(file, ".")
			fileArr[0] = fileArr[0] + "_utf8"
			file = strings.Join(fileArr, ".")
			outPath = dir + file
		}
	}

	fmt.Println("The BIG5 To UTF8 executable v1.0 (2017-11-14):")
	fmt.Println("Settings:")
	fmt.Println("extlist:", extensionWhitelist)
	fmt.Println("chongMaSlash:", replaceChongMaSlash)
	fmt.Println("Unescape String:", unstr)
	fmt.Println("autoDetect:", autoDetect)
	fmt.Println("inPath:", inPath)
	fmt.Println("outPath:", outPath)

	blacklistMap := map[string]bool{}
	if blacklistPath != "" {
		blacklistMap = readFiletoMap(blacklistPath)
		fmt.Println("Blacklist:")
		prettyPrint(blacklistMap)
	}

	skipDirListMap := map[string]bool{}
	if skipDirListPath != "" {
		skipDirListMap = readFiletoMap(skipDirListPath)
		fmt.Println("SkipDirectoryList:")
		prettyPrint(skipDirListMap)
	}

	fromlistMap := map[string]string{}
	if fromlistPath != "" {
		fromlistMap = readFiletoMap_fromlist(fromlistPath)
		fmt.Println("Transform from list:")
		prettyPrint(fromlistMap)
	}

	// start processing
	fmt.Println("Running...")
	start := time.Now()

	if dir {
		done := make(chan struct{})
		defer close(done)

		paths, rejectedPaths, _ := dirutil.WalkService(done, inPath, outPath, extensionWhitelist, blacklistMap, skipDirListMap)
		// TODO: err handle

		var wg sync.WaitGroup
		wg.Add(2)
		// worker group for accepted path
		go func() {
			defer wg.Done()
			dirutil.WorkerGroup(workerPool, func() {
				for filePath := range paths {
					transformFile(filePath.In, filePath.Out, rbuf, wbuf, from, autoDetect, fromlistMap, unstr, replaceChongMaSlash)
				}
			})
		}()

		// worker group for rejected path
		go func() {
			defer wg.Done()
			dirutil.WorkerGroup(workerPool, func() {
				for filePath := range rejectedPaths {
					copyFile(filePath.In, filePath.Out)
				}
			})
		}()
		wg.Wait()

	} else {
		transformFile(inPath, outPath, rbuf, wbuf, from, autoDetect, fromlistMap, unstr, replaceChongMaSlash)
	}

	after := time.Since(start)
	fmt.Println("Total time taken: ", after)
}

func transformFile(inPath string, outPath string, rbuf int, wbuf int, from string, autoDetect bool, fromlistMap map[string]string, unstr bool, replaceChongMaSlash bool) {
	// read file
	in, err := os.Open(inPath)
	check(err)
	defer in.Close()

	// write file
	out, err := os.Create(outPath)
	check(err)
	defer out.Close()

	fromEncode := from
	if autoDetect {
		fromEncode = fileEncodingDetector(in)
		in.Seek(0, 0)
	}
	if _, ok := fromlistMap[inPath]; ok {
		fromEncode = fromlistMap[inPath]
	}
	fromEncode = strings.TrimSpace(fromEncode)
	fromEncode = strings.ToLower(fromEncode)
	if fromEncode == "utf8" || fromEncode == "utf-8" {
		copyFile(inPath, outPath)
		return
	}

	bufin := bufio.NewReaderSize(in, rbuf)
	bufout := bufio.NewWriterSize(out, wbuf)
	fmt.Println("Transforming", inPath, "from", fromEncode)
	transformer, err := fromCJKToUTF8(fromEncode)
	if err != nil {
		fmt.Println(in.Name(), ":", err)
		copyFile(inPath, outPath)
		return
	}
	toUTF8(bufin, bufout, transformer, unstr, replaceChongMaSlash)
}

func copyFile(inPath string, outPath string) {
	// read file
	in, err := os.Open(inPath)
	check(err)
	defer in.Close()

	// write file
	out, err := os.Create(outPath)
	check(err)
	defer out.Close()

	fmt.Println("Copying", inPath)
	io.Copy(out, in)
}

func toUTF8(bufin *bufio.Reader, bufout *bufio.Writer, transformer *encoding.Decoder, unstr bool, replaceChongMaSlash bool) {
	transformReader := transform.NewReader(bufin, transformer)
	scanner := bufio.NewScanner(transformReader)
	buf := make([]byte, startBufSize)
	scanner.Buffer(buf, maxScanTokenSize)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		line := scanner.Text()
		if unstr {
			line = customhtml.UnescapeString(line)
		}
		if replaceChongMaSlash {
			for _, chongMa := range chongMaList {
				line = strings.Replace(line, chongMa+"\\", chongMa, -1)
			}
		}

		_, err := bufout.WriteString(line)
		check(err)
		_, err = bufout.WriteString("\n")
		check(err)

		// using scanner.Bytes() could be faster
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "reading standard input:", err)
	}
	bufout.Flush()
}

func fromCJKToUTF8(from string) (*encoding.Decoder, error) {
	var decoder *encoding.Decoder
	switch strings.ToLower(from) {
	case "gbk", "cp936", "windows-936":
		decoder = simplifiedchinese.GBK.NewDecoder()
	case "gb18030":
		decoder = simplifiedchinese.GB18030.NewDecoder()
	case "gb2312":
		decoder = simplifiedchinese.HZGB2312.NewDecoder()
	case "big5", "big-5", "cp950":
		decoder = traditionalchinese.Big5.NewDecoder()
	case "euc-kr", "euckr", "cp949":
		decoder = korean.EUCKR.NewDecoder()
	case "euc-jp", "eucjp":
		decoder = japanese.EUCJP.NewDecoder()
	case "shift-jis":
		decoder = japanese.ShiftJIS.NewDecoder()
	case "iso-2022-jp", "cp932", "windows-31j":
		decoder = japanese.ISO2022JP.NewDecoder()
	default:
		return decoder, errors.New("Unsupported encoding " + from)
	}
	return decoder, nil
}

func fileEncodingDetector(in *os.File) string {
	detector := chardet.NewHtmlDetector()
	b, err := ioutil.ReadAll(in) // TODO: Should I reset the file cursor after reading this
	check(err)

	result, err := detector.DetectBest(b)
	check(err)
	fmt.Printf("%s : Detected charset is %s\n", in.Name(), result.Charset)
	return result.Charset
}


// utils
func check(e error) {
	if e != nil {
		panic(e)
	}
}

func printUsage() {
	fmt.Println("Readme: https://docs.google.com/document/d/1dZqlYbqmw9tDeVV9DY9M5ctuiAgs1IkMhTD65V_nNgY/edit")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("Input directory:    ./Big5ToUTF8 -dir -in=\"big5files\" [-out=\"utf8files\"] [-from=\"big5\" (default)] [-unstr] [-extlist] [-blacklist=\"blacklist.txt\"] [-skipdirlist=\"skipdirlist.txt\"] [-fromlist=\"fromlist.txt\"]")
	fmt.Println("Input file          ./Big5ToUTF8 -in=\"cdb_threads\" [-out=\"cdb_threads\"] [-from=\"big5\" (default)] [-unstr]")
	fmt.Println("Type Big5ToUTF8 -h for more details")
	fmt.Println("Examples:")
	fmt.Println("./Big5ToUTF8 -dir -in=\"big5files\" -unstr (&#xxxx to char)")
	fmt.Println("./Big5ToUTF8 -in=\"cdb_threads.txt\"")
}

func readFiletoMap(inpath string) map[string]bool {
	// read file
	in, err := os.Open(inpath)
	check(err)
	defer in.Close()

	fileMap := map[string]bool{}
	scanner := bufio.NewScanner(in)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) > 0 { // ... remember to check or you will skip entire target dir
			line = strings.TrimSpace(line)
			line = filepath.Join(inPath, line)
			fileMap[line] = true
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "reading standard input:", err)
	}

	return fileMap
}

func readFiletoMap_fromlist(inpath string) map[string]string {
	// read file
	in, err := os.Open(inpath)
	check(err)
	defer in.Close()

	var currentEncode string
	fileMap := map[string]string{}
	scanner := bufio.NewScanner(in)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) > 0 {
			line = strings.TrimSpace(line)
			if line[0] == ':' {
				currentEncode = line[1:]
				currentEncode = strings.ToLower(currentEncode)
				continue
			}
			line = filepath.Join(inPath, line)
			fileMap[line] = currentEncode
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "reading standard input:", err)
	}

	return fileMap
}

func prettyPrint(x interface{}) {
	b, err := json.MarshalIndent(x, "", "  ")
	if err != nil {
		fmt.Println("error:", err)
	}
	fmt.Println(string(b))
}

//func big5ToUTF8_GetArgs(args ...interface{}) (bar *uiprogress.Bar, err error) {
//	if len(args) < 1 {
//		return
//	}
//
//	for i, p := range args {
//		switch i {
//		case 0: // ProgressBar
//			param, ok := p.(*uiprogress.Bar)
//			if !ok {
//				err = errors.New("1st parameter not type *uiprogress.Bar.")
//				return
//			}
//			bar = param
//
//		default:
//			err = errors.New("Wrong parameter count.")
//			return
//		}
//	}
//	return
//}

// Experimental
func big5ToUTF8Experimental(in *os.File, out *os.File, rbuf int, wbuf int, n int) {
	bufin := bufio.NewReaderSize(in, rbuf)
	bufout := bufio.NewWriterSize(out, wbuf)

	jobs := fileSource(bufin)
	results := TransformToUTF8(jobs)
	for line := range results {
		_, err := bufout.WriteString(line)
		check(err)
	}
	bufout.Flush()
}

func fileSource(in *bufio.Reader) <-chan string {
	jobs := make(chan string)
	go func() {
		scanner := bufio.NewScanner(in)
		for scanner.Scan() {
			line := scanner.Text()
			jobs <- line
		}
		if err := scanner.Err(); err != nil {
			fmt.Fprintln(os.Stderr, "reading standard input:", err)
		}
		close(jobs)
	}()
	return jobs
}

func TransformToUTF8(in <-chan string) <-chan string {
	results := make(chan string)
	go func() {
		for line := range in {
			result, _, err := transform.String(traditionalchinese.Big5.NewDecoder(), line)
			check(err)
			result = customhtml.UnescapeString(result)
			result = result + "\n"

			results <- result
		}
		close(results)
	}()
	return results
}

// TODO: split file, check line, ui, error check, custom text process func, encoding detect

// Split file: existing methods: mapReduce
// Custom text process func: copy entire standard lib and modify

// Pitfall:
// Problem 1:
// Using progress bar from different third-party result in different speed in different platforms.
// Solution: Not using any progress bar

// Problem 2:
// Order of reader wrapper will affect the performance, they use different buffer size
// Solution: better to wrap raw reader to bufio first
