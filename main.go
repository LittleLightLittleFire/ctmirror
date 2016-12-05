package main

import (
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"bitbucket.org/liamstask/goose/lib/goose"
	"github.com/jmoiron/sqlx"

	ct "github.com/google/certificate-transparency/go"
	"github.com/google/certificate-transparency/go/client"
	"github.com/google/certificate-transparency/go/jsonclient"
	"github.com/google/certificate-transparency/go/scanner"

	httpclient "github.com/mreiferson/go-httpclient"
)

func main() {
	log.SetFlags(log.Lshortfile | log.LstdFlags | log.Lmicroseconds)

	environment := os.Getenv("ENV")
	if environment == "" {
		environment = "development"
	}

	dbFolder := os.Getenv("DB_FOLDER")
	if dbFolder == "" {
		dbFolder = "db"
	}

	logURL := os.Getenv("LOG_URL")
	if logURL == "" {
		logURL = "http://ct.googleapis.com/aviator"
	}

	// Connect to the database
	conf, err := goose.NewDBConf(dbFolder, environment, "")
	if err != nil {
		log.Fatalln("Failed to read db/dbconf.yml:", err)
	}

	rawDB, err := goose.OpenDBFromDBConf(conf)
	if err != nil {
		log.Fatalln("Failed to open db:", err)
	}

	db := sqlx.NewDb(rawDB, conf.Driver.Name)
	if err := db.Ping(); err != nil {
		log.Fatalln("Failed to ping db:", err)
	}

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
		NumWorkers:    runtime.GOMAXPROCS(-1),
		ParallelFetch: runtime.GOMAXPROCS(-1),
		StartIndex:    0,
		Quiet:         false,
	}
	if err := db.Get(&scannerOptions.StartIndex, "SELECT COALESCE(MAX(ID), -1)+1 FROM entries"); err != nil {
		log.Fatalln("Failed to get current entry:", err)
	}

	// Set a signal handler to prevent data corruption
	interrupted := make(chan os.Signal, 1)
	signal.Notify(interrupted, os.Interrupt, syscall.SIGTERM)

	fixUTF8 := func(s string) string {
		return string([]rune(s))
	}

	found := func(entry *ct.LogEntry) {
		// Exit here if interrupted
		select {
		case <-interrupted:
			os.Exit(0)
		default:
		}

		if _, err := db.Exec(
			db.Rebind("INSERT INTO entries VALUES (?, ?, ?, ?, ?, ?, ?)"),
			entry.Index,
			fixUTF8(entry.X509Cert.Issuer.CommonName),
			fixUTF8(strings.Join(entry.X509Cert.Issuer.Organization, ";")),
			fixUTF8(entry.X509Cert.Subject.CommonName),
			fixUTF8(strings.Join(entry.X509Cert.Subject.Organization, ";")),
			entry.X509Cert.NotBefore,
			entry.X509Cert.NotAfter,
		); err != nil {
			log.Fatalln("Failed to insert entry:", err)
		}

		for _, v := range entry.X509Cert.DNSNames {
			if _, err := db.Exec(
				db.Rebind("INSERT INTO dnsnames (entry, dnsname) VALUES (?, ?)"),
				entry.Index,
				fixUTF8(v),
			); err != nil {
				log.Fatalln("Failed to insert entry:", err)
			}
		}
	}

	scanner := scanner.NewScanner(lc, scannerOptions)
	if err := scanner.Scan(found, found); err != nil {
		log.Fatalln("Failed to scan:", err)
	}
}
