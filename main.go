package main

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"

	"github.com/fsnotify/fsnotify"
)

var (
	tlsConfig = &tls.Config{
		// Avoids most of the memorably-named TLS attacks
		MinVersion: tls.VersionTLS12,
		// Causes servers to use Go's default ciphersuite preferences,
		// which are tuned to avoid attacks. Does nothing on clients.
		PreferServerCipherSuites: true,
		// Only use curves which have constant-time implementations
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
		},
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  x509.NewCertPool(),
	}
	crl                      = &crlMutex{}
	stsDefaultDuration int64 = 900         // 900 Seconds = 15 minutes
	awsDefaultRegion         = "sa-east-1" // São Paulo
	awsSession         *session.Session
	awsStsService      *sts.STS
)

type crlMutex struct {
	sync.RWMutex
	Value *pkix.CertificateList
}

func main() {
	configPtr := flag.String("config", "", "Config file to be used. Must be JSON format!")
	flag.Parse()

	var conf config
	if *configPtr == "" {
		err := parseConfig(&conf)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		err := parseConfigFile(&conf, *configPtr)
		if err != nil {
			log.Fatal(err)
		}
	}

	if conf.AwsRegion != "" {
		awsDefaultRegion = conf.AwsRegion
	}
	if conf.StsSessionDurationSeconds > 0 {
		stsDefaultDuration = conf.StsSessionDurationSeconds
	}

	log.Printf("INFO - AWS region set to \"%v\"", awsDefaultRegion)
	log.Printf("INFO - AWS STS duration set to \"%v\" seconds", stsDefaultDuration)

	var err error

	// CA
	caCertPEM, err := ioutil.ReadFile(conf.ClientCA)
	if err != nil {
		log.Fatal("ERROR - Reading CA PEM file - ", err)
	}
	block, _ := pem.Decode(caCertPEM)
	if block == nil {
		log.Fatal("ERROR - Failed to decode CA PEM file")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatal("ERROR - Parse CA PEM file - ", err)
	}
	tlsConfig.ClientCAs.AddCert(caCert)

	// CRL
	err = loadCRL(conf, caCert)
	if err != nil {
		log.Fatal(err)
	}

	// AWS
	awsSession, err = session.NewSessionWithOptions(session.Options{
		Config: aws.Config{Region: aws.String(awsDefaultRegion)},
	})
	if err != nil {
		log.Fatal(err)
	}
	awsStsService = sts.New(awsSession)

	// Channel and goroutine to handle interruption
	signalChan := make(chan os.Signal, 1)
	done := make(chan struct{})
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		// Wait for interruption signal, can be CTRL-C
		// or error from one of goroutine's below
		<-signalChan
		signal.Stop(signalChan)
		close(signalChan)

		log.Println("INFO - Interrupt")
		close(done)
	}()

	// Watch CRL file, if it changes a goroutine will load it again
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal("ERROR - Creating file watcher - ", err)
	}
	defer watcher.Close()

	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					signalChan <- os.Interrupt
				}
				log.Println("EVENT - ", event)
				if event.Op&fsnotify.Write == fsnotify.Write {
					err := loadCRL(conf, caCert)
					if err != nil {
						log.Println(err)
					}
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					signalChan <- os.Interrupt
				}
				log.Println("ERROR - ", err)
			}
		}
	}()

	// out of the box fsnotify can watch a single file, or a single directory
	err = watcher.Add(conf.CRL)
	if err != nil {
		log.Fatal("ERROR - Watching file - ", err)
	}

	// Listen on HTTPS
	go listenAndServeHTTPS(conf, signalChan)

	// Wait for cleanup be done
	<-done
}

func loadCRL(conf config, caCert *x509.Certificate) error {
	crlPEM, err := ioutil.ReadFile(conf.CRL)
	if err != nil {
		return fmt.Errorf("ERROR - Reading CRL PEM file - %v", err.Error())
	}

	crlParsed, err := x509.ParseCRL(crlPEM)
	if err != nil {
		return fmt.Errorf("ERROR - Parse CRL PEM file - %v", err.Error())
	}

	err = caCert.CheckCRLSignature(crlParsed)
	if err != nil {
		return fmt.Errorf("ERROR - Checking CRL signature - %v", err.Error())
	}

	if crlParsed.HasExpired(time.Now()) {
		log.Println("WARNING - CRL file is expired since", crlParsed.TBSCertList.NextUpdate)
	}

	crl.Lock()
	defer crl.Unlock()
	crl.Value = crlParsed

	return nil
}

func listenAndServeHTTPS(conf config, ch chan<- os.Signal) {
	httpsMux := http.NewServeMux()
	httpsMux.HandleFunc("/token/", dumpRequestHandler(allowedMethodHandler(secureHandler(tokenHandler))))

	addr := fmt.Sprintf("%v:%v", conf.Address, conf.SecurePort)
	log.Printf("INFO - HTTPS listen on \"%v\"", addr)
	server := &http.Server{
		Addr:      addr,
		TLSConfig: tlsConfig,
		Handler:   httpsMux,
	}

	err := server.ListenAndServeTLS(conf.Certificate, conf.CertificateKey)
	if err != nil {
		log.Println("ERROR - HTTPS", err)
	}
	ch <- os.Interrupt
}

func dumpRequestHandler(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "" {
			username, _, ok := r.BasicAuth()
			if ok {
				r.Header.Set("Authorization", "Basic "+username)
			}
		}
		dump, err := httputil.DumpRequest(r, false)
		if err != nil {
			log.Println("ERROR - ", err)
			return
		}
		log.Printf("%q", dump)
		if auth != "" {
			r.Header.Set("Authorization", auth)
		}

		fn(w, r)
	}
}

func allowedMethodHandler(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}

		fn(w, r)
	}
}

func isCertificateRevoked(cert *x509.Certificate) bool {
	// Reference: https://github.com/cloudflare/cfssl/blob/master/revoke/revoke.go
	crl.RLock()
	defer crl.RUnlock()
	for _, revoked := range crl.Value.TBSCertList.RevokedCertificates {
		if cert.SerialNumber.Cmp(revoked.SerialNumber) == 0 {
			return true
		}
	}
	return false
}

func secureHandler(fn func(http.ResponseWriter, *http.Request, string, string, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// log.Println("Subject: ", r.TLS.PeerCertificates[0].Subject)
		// log.Println("RemoteAddr: ", r.RemoteAddr)
		// log.Println("Names: ", r.TLS.PeerCertificates[0].Subject.Names)
		// log.Println("EmailAddresses: ", r.TLS.PeerCertificates[0].EmailAddresses)
		// log.Println("CRLDistributionPoints: ", r.TLS.PeerCertificates[0].CRLDistributionPoints)

		// As it uses tls.RequireAndVerifyClientCert option, it will always have a client certificate signed by our CA.
		// But it needs to verify it client certificate is valid and not revoked.
		// r.TLS.PeerCertificates[0] is the client certificate.

		remoteAddr := strings.Split(r.RemoteAddr, ":")[0]
		remoteNames, err := net.LookupAddr(remoteAddr)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// log.Println("RemoteNames: ", remoteNames)

		opts := x509.VerifyOptions{
			Roots:     tlsConfig.ClientCAs,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			DNSName:   remoteNames[0],
		}
		_, err = r.TLS.PeerCertificates[0].Verify(opts)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		// Check if cliente certificate is revoked
		if isCertificateRevoked(r.TLS.PeerCertificates[0]) {
			// log.Println("INFO - Serial number match: client certificate is revoked.")
			http.Error(w, "Client certificate is revoked", http.StatusUnauthorized)
			return
		}

		// Certificate MUST have at least one e-mail address on SAN (Subject alternative names) or on Subject (OID 1.2.840.113549.1.9.1)
		// The preference is SAN first than Subject.
		// As SAN is an array, it will be the first e-mail from this arrays.
		// This e-mail will be the session name when it assume role.
		email := ""
		if len(r.TLS.PeerCertificates[0].EmailAddresses) > 0 {
			email = r.TLS.PeerCertificates[0].EmailAddresses[0]
		} else {
			// Reference: http://www.alvestrand.no/objectid/1.2.840.113549.1.9.1.html
			emailOID := []int{1, 2, 840, 113549, 1, 9, 1}
			email = getFromCertificateSubject(r.TLS.PeerCertificates[0], emailOID)
		}
		if email == "" {
			http.Error(w, "Certificate does not have any valid e-mail on SAN or Subject", http.StatusUnauthorized)
			return
		}

		// Certificate subject UID is the ExternalID when assume role.
		// If certificate does not contain UID, it will assume role without ExternalID.
		// Role must request an ExternalID to have this second fact of validation.
		// Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user_externalid.html
		// Reference: http://www.alvestrand.no/objectid/0.9.2342.19200300.100.1.1.html
		userOID := []int{0, 9, 2342, 19200300, 100, 1, 1}
		externalID := getFromCertificateSubject(r.TLS.PeerCertificates[0], userOID)

		// Certificate  subject "CommonName" (CN) is the Role ARN to be assumed
		cn := r.TLS.PeerCertificates[0].Subject.CommonName

		fn(w, r, cn, externalID, email)
	}
}

func tokenHandler(w http.ResponseWriter, r *http.Request, roleArn string, externalID string, sessionName string) {
	out, err := getToken(roleArn, externalID, stsDefaultDuration, sessionName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Response
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	err = json.NewEncoder(w).Encode(out)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func getToken(roleArn string, externalID string, duration int64, sessionName string) (*sts.AssumeRoleOutput, error) {
	// log.Print("RoleArn: ", roleArn)
	// log.Print("ExternalID: ", externalID)
	// log.Print("Duration: ", duration)
	// log.Print("SessionName: ", sessionName)

	input := &sts.AssumeRoleInput{}
	input.SetDurationSeconds(duration).SetRoleArn(roleArn).SetRoleSessionName(sessionName)
	if externalID != "" {
		input.SetExternalId(externalID)
	}
	err := input.Validate()
	if err != nil {
		return nil, err
	}

	// AWS Assume Role
	return awsStsService.AssumeRole(input)
}

func getFromCertificateSubject(cert *x509.Certificate, oid []int) string {
	for _, n := range cert.Subject.Names {
		if n.Type.Equal(oid) {
			if v, ok := n.Value.(string); ok {
				return v
			}
		}
	}
	return ""
}

// Config : Struct to match JSON config file
type config struct {
	Address                   string
	SecurePort                int
	Certificate               string
	CertificateKey            string
	ClientCA                  string
	CRL                       string
	AwsRegion                 string
	StsSessionDurationSeconds int64
}

// ParseConfig : Load default config file, in JSON format
func parseConfig(v interface{}) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	config := exe + ".conf"

	return parseConfigFile(v, config)
}

// ParseConfigFile : Parse config file to some struct.
// Config file must be in JSON format.
func parseConfigFile(v interface{}, fileName string) error {
	f, err := os.Open(fileName)
	if err != nil {
		return err
	}
	defer f.Close()

	err = json.NewDecoder(f).Decode(v)
	if err != nil {
		return err
	}
	return nil
}
