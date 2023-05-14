package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cheggaaa/pb"
	"github.com/fatih/color"
	"github.com/vicanso/go-axios"
)

type sParams struct {
	inputFile  string
	outputfile string
	threads    int
}

var exploitableWebsites []string
var params sParams

func getListWebsite(file string) []string {

	var list []string

	fd, err := os.Open(file)
	if err != nil {
		log.Fatal(err)
	}
	defer fd.Close()

	scanner := bufio.NewScanner(fd)

	const maxCapacity int = 10000000 // your required line length
	buf := make([]byte, maxCapacity)
	scanner.Buffer(buf, maxCapacity)

	for scanner.Scan() {
		list = append(list, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	return list
}

func checkGitConfig(website string) string {
	resp, err := axios.Get("https://" + website + "/.git/config")
	if err != nil {
		return ""
	}

	if strings.Contains(string(resp.Data), "[core]") {
		appendToFile(website)
		exploitableWebsites = append(exploitableWebsites, ".git/config found: " + website)
	
		return ".git/config found"
	}

	return ""
}
func checkEnvFile(website string) string {
	resp, err := axios.Get("https://" + website + "/.env")
	if err != nil {
		return ""
	}

	if strings.Contains(string(resp.Data), "SENSITIVE_INFORMATION") {
		appendToFile(website)
		exploitableWebsites = append(exploitableWebsites, ".env found :" +website)
		return ".env found"
	}

	return ""
}

func checkInfo(website string) string {
	resp, err := axios.Get("https://" + website + "/info.php")
	if err != nil {
		return ""
	}

	if strings.Contains(string(resp.Data), "SENSITIVE_INFORMATION") {
		appendToFile(website)
		exploitableWebsites = append(exploitableWebsites, "Info.php found: "+website)
		return "Info.php found"
	}

	return ""
}


func checkPhpMyAdmin(website string) string {
    resp, err := axios.Get("https://" + website + "/phpmyadmin")
    if err != nil {
        return ""
    }

    if resp.Status == 200 && strings.Contains(string(resp.Data), "phpMyAdmin") {
        exploitableWebsites = append(exploitableWebsites,"Phpmyadmin found :" + website)
        appendToFile(website)
        return "Phpmyadmin found"
    }

    return ""
}


func checkSqlInjection(website string) string {
	resp, err := axios.Get("https://" + website + "/?id=1';SELECT%20*%20FROM%20users%20WHERE%201=1--'")
	if err != nil {
		return ""
	}

	if resp.Status == 500 && strings.Contains(string(resp.Data), "SQL syntax") {
		exploitableWebsites = append(exploitableWebsites,"Sql injection found :" + website)
		appendToFile(website)
		return "Sql injection found"
	}

	return ""
}

func appendToFile(website string) {
	f, err := os.OpenFile(params.outputfile,
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println(err)
	}
	defer f.Close()
	if _, err := f.WriteString(website + "\n"); err != nil {
		log.Println(err)
	}
}

func printHeader() {
	color.Red(`
	  ▄████  ▒█████    █████▒██▓ ███▄    █ ▓█████▄ ▓█████  ██▀███  
	 ██▒ ▀█▒▒██▒  ██▒▓██   ▒▓██▒ ██ ▀█   █ ▒██▀ ██▌▓█   ▀ ▓██ ▒ ██▒
	▒██░▄▄▄░▒██░  ██▒▒████ ░▒██▒▓██  ▀█ ██▒░██   █▌▒███   ▓██ ░▄█ ▒
	░▓█  ██▓▒██   ██░░▓█▒  ░░██░▓██▒  ▐▌██▒░▓█▄   ▌▒▓█  ▄ ▒██▀▀█▄  
	░▒▓███▀▒░ ████▓▒░░▒█░   ░██░▒██░   ▓██░░▒████▓ ░▒████▒░██▓ ▒██▒
	 ░▒   ▒ ░ ▒░▒░▒░  ▒ ░   ░▓  ░ ▒░   ▒ ▒  ▒▒▓  ▒ ░░ ▒░ ░░ ▒▓ ░▒▓░
	  ░   ░   ░ ▒ ▒░  ░      ▒ ░░ ░░   ░ ▒░ ░ ▒  ▒  ░ ░  ░  ░▒ ░ ▒░
	░ ░   ░ ░ ░ ░ ▒   ░ ░    ▒ ░   ░   ░ ░  ░ ░  ░    ░     ░░   ░ 
		  ░     ░ ░          ░           ░    ░       ░  ░   ░     
	`)
}

func main() {

	fmt.Print("\033[H\033[2J")
	printHeader()
	// sti.Init("MTYzLjE3Mi4xNzMuMzY=")
	flag.StringVar(&params.inputFile, "i", "", "File input with all websites")
	flag.StringVar(&params.outputfile, "o", "exploitable.log", "(Optional) File where you want to save the results")
	t := flag.Int("t", 20, "(Optional) threads number")
	flag.Parse()

	if params.inputFile == "" {
		flag.PrintDefaults()
		return
	}

	params.threads = *t

	listWebsite := getListWebsite(params.inputFile)
	color.Magenta("%s %d %s", "Scanning", len(listWebsite), "websites...")
	fmt.Println("")

	concurrentGoroutines := make(chan struct{}, params.threads)
	var wg sync.WaitGroup

	bar := pb.StartNew(len(listWebsite))

	totalLinks := 0

	for _, website := range listWebsite {
		wg.Add(1)

    go func(website string) {
        defer wg.Done()
        concurrentGoroutines <- struct{}{}

        checkGitConfig(website)
        checkEnvFile(website)
		checkPhpMyAdmin(website)
		checkSqlInjection(website)
		checkInfo(website)
        
		time.Sleep(3 * time.Second)

        <-concurrentGoroutines
        if len(exploitableWebsites) != totalLinks {
            fmt.Print("\033[H\033[2J")
            printHeader()
            color.Magenta("%s %d %s", "Scanning", len(listWebsite), "websites...")
            fmt.Println("")
            for _, elem := range exploitableWebsites {
				if strings.Contains(elem, "Sql"){
					color.Yellow(elem)
				}
				if strings.Contains(elem, "Phpmyadmin") {
					color.Red(elem)
				}
				if strings.Contains(elem, "Info.php") {
					color.Blue(elem)
				}
				if strings.Contains(elem, ".env") {
					color.Blue(elem)
				}
				if strings.Contains(elem, ".git") {
					color.Green(elem)
				}
            }
            fmt.Println("")
            totalLinks = len(exploitableWebsites)
        }
        bar.Increment()
    }(website)
}

	wg.Wait()
	bar.Finish()
}