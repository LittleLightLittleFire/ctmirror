package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	ct "github.com/google/certificate-transparency/go"
	"github.com/google/certificate-transparency/go/client"
	"github.com/google/certificate-transparency/go/jsonclient"
	"github.com/google/certificate-transparency/go/scanner"

	httpclient "github.com/mreiferson/go-httpclient"
)

func main() {
	log.SetFlags(log.Lshortfile | log.LstdFlags | log.Lmicroseconds)

	var startIndex int64
	var logURL string

	flag.Int64Var(&startIndex, "start", 0, "starting index of the dump")
	flag.StringVar(&logURL, "log", "http://ct.googleapis.com/pilot", "the ct log url")

	dataDir := "data/"
	entryFileName := path.Join(dataDir, "entries.csv")
	dnsFileName := path.Join(dataDir, "dnsnames.csv")

	// Create the data directory
	if err := os.MkdirAll(dataDir, 0744); err != nil {
		log.Fatalln("Failed to make data directory:", err)
	}

	// Open files for writing
	entryFile, err := os.OpenFile(entryFileName, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalln("Failed to open entry file for writing:", err)
	}
	defer entryFile.Close()

	dnsFile, err := os.OpenFile(dnsFileName, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalln("Failed to open dns file for writing:", err)
	}
	defer dnsFile.Close()

	// Set up writers
	entryFileWriter := bufio.NewWriter(entryFile)
	defer entryFileWriter.Flush()

	dnsFileWriter := bufio.NewWriter(dnsFile)
	defer dnsFileWriter.Flush()

	// Create the CT log client
	lc, err := client.New(logURL,
		&http.Client{
			Transport: &httpclient.Transport{
				ConnectTimeout:        10 * time.Second,
				RequestTimeout:        30 * time.Second,
				ResponseHeaderTimeout: 30 * time.Second,
				MaxIdleConnsPerHost:   10,
				DisableKeepAlives:     false,
			},
		}, jsonclient.Options{},
	)
	if err != nil {
		log.Fatalln("Failed to create CT client:", err)
	}

	// Set the start index
	scannerOptions := scanner.ScannerOptions{
		Matcher:       &scanner.MatchAll{},
		PrecertOnly:   false,
		BatchSize:     5000,
		NumWorkers:    1,
		ParallelFetch: runtime.GOMAXPROCS(-1),
		StartIndex:    0,
		Quiet:         false,
	}

	// Set a signal handler to prevent data corruption
	interrupted := make(chan os.Signal, 1)
	signal.Notify(interrupted, os.Interrupt, syscall.SIGTERM)

	checkError := func(_ int, err error) {
		if err != nil {
			log.Fatalln(err)
		}
	}

	found := func(entry *ct.LogEntry) {
		// Exit here if interrupted
		select {
		case <-interrupted:
			os.Exit(0)
		default:
		}

		// It is either a certificate or a pre-certificate
		cert := entry.X509Cert
		if cert == nil {
			cert = &entry.Precert.TBSCertificate
		}

		checkError(entryFileWriter.WriteString(fmt.Sprint(entry.Index)))
		checkError(entryFileWriter.WriteString(","))
		checkError(entryFileWriter.WriteString(strconv.Quote(cert.Issuer.CommonName)))
		checkError(entryFileWriter.WriteString(","))
		checkError(entryFileWriter.WriteString(strconv.Quote(strings.Join(cert.Issuer.Organization, ";"))))
		checkError(entryFileWriter.WriteString(","))
		checkError(entryFileWriter.WriteString(strconv.Quote(cert.Subject.CommonName)))
		checkError(entryFileWriter.WriteString(","))
		checkError(entryFileWriter.WriteString(strconv.Quote(strings.Join(cert.Subject.Organization, ";"))))
		checkError(entryFileWriter.WriteString("\n"))

		for _, v := range cert.DNSNames {
			checkError(dnsFileWriter.WriteString(fmt.Sprint(entry.Index)))
			checkError(dnsFileWriter.WriteString(","))
			checkError(dnsFileWriter.WriteString(strconv.Quote(v)))
			checkError(dnsFileWriter.WriteString("\n"))
		}
	}

	scanner := scanner.NewScanner(lc, scannerOptions)
	if err := scanner.Scan(found, found); err != nil {
		log.Fatalln("Failed to scan:", err)
	}
}
