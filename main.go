package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"github.com/foomo/simplecert"
	"github.com/spf13/cobra"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

var (
	Domains     string
	EMail       string
	Username    string
	Password    string
	StoragePath string
)

func main() {
	var rootCmd = &cobra.Command{
		Use:  "build_artifact_server",
		RunE: runServer,
	}

	rootCmd.PersistentFlags().StringVarP(&Domains, "domains", "d", "", "comma-separated list of domains for letsencrypt")
	rootCmd.PersistentFlags().StringVarP(&EMail, "email", "e", "", "email address for letsencrypt")
	rootCmd.PersistentFlags().StringVarP(&Username, "username", "u", "", "http basic auth username")
	rootCmd.PersistentFlags().StringVarP(&Password, "password", "p", "", "http basic auth password")
	rootCmd.PersistentFlags().StringVarP(&StoragePath, "storage-path", "s", "", "path to data storage folder")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

type HttpToHttpsRedirectHandler struct{}

func (h HttpToHttpsRedirectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	target := "https://" + r.Host + r.URL.Path
	if len(r.URL.RawQuery) > 0 {
		target += "?" + r.URL.RawQuery
	}
	http.Redirect(w, r, target, http.StatusTemporaryRedirect)
}

type HttpsHandler struct{}

func (h HttpsHandler) IsAuthorized(r *http.Request) bool {
	auth_header := r.Header.Get("Proxy-Authorization")
	if auth_header == "" {
		return false
	}
	const prefix = "Basic "
	if !strings.HasPrefix(auth_header, prefix) {
		return false
	}
	decoded_bytes, err := base64.StdEncoding.DecodeString(auth_header[len(prefix):])
	if err != nil {
		return false
	}
	decoded_string := string(decoded_bytes)
	split_at := strings.IndexByte(decoded_string, ':')
	if split_at < 0 {
		return false
	}
	if Username != decoded_string[:split_at] {
		return false
	}
	if Password != decoded_string[split_at+1:] {
		return false
	}
	return true
}

func (h HttpsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.IsAuthorized(r) {
		w.Header().Add("Proxy-Authenticate", "Basic")
		w.WriteHeader(407)
		return
	}
	w.WriteHeader(200)
	w.Write([]byte("Hello!"))
}

func runServer(cmd *cobra.Command, args []string) error {
	if Domains == "" || EMail == "" || Username == "" || Password == "" {
		return cmd.Usage()
	}
	for {
		log.Println("Acquiring SSL certificate ...")

		certificate_config := simplecert.Config{
			RenewBefore:          30 * 24,
			CheckInterval:        999 * 24 * time.Hour,
			SSLEmail:             EMail,
			DirectoryURL:         "https://acme-v02.api.letsencrypt.org/directory",
			HTTPAddress:          ":80",
			TLSAddress:           ":443",
			CacheDirPerm:         0700,
			Domains:              strings.Split(Domains, ","),
			CacheDir:             "letsencrypt",
			DNSProvider:          "",
			Local:                false,
			UpdateHosts:          true,
			DNSServers:           []string{},
			WillRenewCertificate: func() {},
			DidRenewCertificate:  func() {},
		}

		cleanup := func() {
			os.Exit(0)
		}
		certificate_bot, err := simplecert.Init(&certificate_config, cleanup)
		if err != nil {
			return fmt.Errorf("ssl certificate setup failed: %w", err)
		}

		tls_config := &tls.Config{}
		tls_config.MinVersion = tls.VersionTLS12
		tls_config.PreferServerCipherSuites = true
		tls_config.CipherSuites = []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		}
		tls_config.CurvePreferences = []tls.CurveID{
			tls.CurveP256,
			tls.CurveP384,
			tls.CurveP521,
		}
		tls_config.GetCertificate = certificate_bot.GetCertificateFunc()

		http_server := &http.Server{
			Addr:    ":80",
			Handler: HttpToHttpsRedirectHandler{},
		}
		https_server := &http.Server{
			Addr:      ":443",
			Handler:   HttpsHandler{},
			TLSConfig: tls_config,
		}

		current_certificate_data, err := tls_config.GetCertificate(&tls.ClientHelloInfo{})
		if err != nil {
			return fmt.Errorf("reading current ssl certificate failed: %w", err)
		}

		current_certificate, err := x509.ParseCertificate(current_certificate_data.Certificate[0])
		if err != nil {
			return fmt.Errorf("parsing current ssl certificate failed: %w", err)
		}

		should_restart_for_certificate_renewal_at := current_certificate.NotAfter.Add(-16 * 24 * time.Hour)

		go func() {
			if err := http_server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("HTTP ListenAndServe FAILED: %w", err)
			}
		}()
		go func() {
			if err := https_server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				log.Fatalf("HTTPS ListenAndServeTLS FAILED: %w", err)
			}
		}()

		log.Println("Server running :)")

		<-time.NewTimer(should_restart_for_certificate_renewal_at.Sub(time.Now())).C

		log.Println("Server restarting for certificate renewal ...")

		shutdown_timeout_context, shutdown_timeout_cancel := context.WithTimeout(context.Background(), 5*time.Second)

		err = http_server.Shutdown(shutdown_timeout_context)
		if err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("HTTP Shutdown FAILED: %w", err)
		}
		err = https_server.Shutdown(shutdown_timeout_context)
		if err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("HTTPS Shutdown FAILED: %w", err)
		}

		shutdown_timeout_cancel()
	}
}
