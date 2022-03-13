package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/foomo/simplecert"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var (
	Domains               string
	EMail                 string
	Username              string
	Password              string
	StoragePath           string
	SelfSignedCertificate bool
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
	rootCmd.PersistentFlags().BoolVar(&SelfSignedCertificate, "self-signed-certificate", false, "create self-signed certificate with mkcert instead of using letsencrypt")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

type HttpToHttpsRedirectHandler struct{}

var StaticFileServer http.Handler

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
		auth_header = r.Header.Get("Authorization")
	}
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
	if r.Header.Get("Proxy-Authorization") != "" {
		// we're in HTTP proxy mode
		if !h.IsAuthorized(r) {
			w.Header().Add("Proxy-Authenticate", "Basic")
			w.WriteHeader(407)
			w.Write([]byte("407 Proxy Authentication Required"))
			return
		}

		if r.Method != "GET" {
			w.WriteHeader(400)
			w.Write([]byte("400 Bad Request"))
			return
		}

		proxy_file_safe_host := regexp.MustCompile("[^a-zA-Z0-9.]+").ReplaceAllString(r.Host, "_")
		proxy_file_path := path.Clean("/" + r.URL.Path)
		if strings.HasSuffix(proxy_file_path, "/") {
			proxy_file_path += "___SLASH___"
		}
		proxy_file_reference := path.Join(proxy_file_safe_host, proxy_file_path)
		target_path := path.Join(StoragePath, "files", proxy_file_reference)

		_, err := os.Stat(target_path)
		if errors.Is(err, os.ErrNotExist) {
			log.Println("PROXY DOWNLOAD", proxy_file_reference, "<=", r.URL)
			err = os.MkdirAll(path.Dir(target_path), 0700)
			if err != nil {
				w.WriteHeader(500)
				w.Write([]byte(fmt.Sprintf("500 Cannot mkdir: %v", err)))
				return
			}

			source, err := http.Get(r.URL.String())
			if err != nil {
				w.WriteHeader(500)
				w.Write([]byte(fmt.Sprintf("500 Cannot download your file: %v", err)))
				return
			}
			defer source.Body.Close()

			target_writer, err := os.OpenFile(target_path, os.O_WRONLY|os.O_CREATE, 0600)
			if err != nil {
				w.WriteHeader(500)
				w.Write([]byte(fmt.Sprintf("500 Cannot write your file: %v", err)))
				return
			}
			defer target_writer.Close()

			_, err = io.Copy(target_writer, source.Body)
			if err != nil {
				w.WriteHeader(500)
				w.Write([]byte(fmt.Sprintf("500 Cannot write your file: %v", err)))
				return
			}
		}

		r.URL.Host = "127.0.0.1"
		r.URL.Path = proxy_file_reference
		log.Println("PROXY FILE", r.URL.Path)
		StaticFileServer.ServeHTTP(w, r)
		return
	} else {
		// we're in webserver mode
		if !h.IsAuthorized(r) {
			w.Header().Add("WWW-Authenticate", "Basic")
			w.WriteHeader(401)
			w.Write([]byte("401 Unauthorized"))
			return
		}

		const files = "/files/"
		if strings.HasPrefix(r.URL.Path, files) {
			r.URL.Path = r.URL.Path[len(files):]
			log.Println("STATIC FILE", r.URL.Path)
			StaticFileServer.ServeHTTP(w, r)
			return
		}
		const upload = "/upload"
		if strings.HasPrefix(r.URL.Path, upload) {
			if r.Method != "POST" && r.Method != "PUT" {
				w.WriteHeader(400)
				w.Write([]byte("400 Bad Request"))
				return
			}
			upload_reader, upload_info, err := r.FormFile("file")
			if err != nil {
				w.WriteHeader(500)
				w.Write([]byte(fmt.Sprintf("500 Cannot handle your upload: %v", err)))
				return
			}

			target_folder_name := r.Header.Get("X-Folder")
			if target_folder_name == "" {
				target_folder_name = uuid.New().String()
			}
			target_folder := path.Join(StoragePath, "files", target_folder_name)
			os.Mkdir(target_folder, 0700)
			target_filename := upload_info.Filename
			if target_filename == "" {
				target_filename = uuid.New().String()
			}

			log.Println("FILE UPLOAD", path.Join(target_folder_name, target_filename))

			target_path := path.Join(target_folder, target_filename)
			target_writer, err := os.OpenFile(target_path, os.O_WRONLY|os.O_CREATE, 0600)
			if err != nil {
				w.WriteHeader(500)
				w.Write([]byte(fmt.Sprintf("500 Cannot write your file: %v", err)))
				return
			}
			defer target_writer.Close()

			_, err = io.Copy(target_writer, upload_reader)
			if err != nil {
				w.WriteHeader(500)
				w.Write([]byte(fmt.Sprintf("500 Cannot write your file: %v", err)))
				return
			}

			w.WriteHeader(200)
			w.Write([]byte(path.Join("files", target_folder_name, target_filename)))
			return
		}

		w.WriteHeader(418)
		w.Write([]byte("418 I'm a teapot"))
	}
}

func runServer(cmd *cobra.Command, args []string) error {
	if Domains == "" || (EMail == "" && !SelfSignedCertificate) || Username == "" || Password == "" || StoragePath == "" {
		return cmd.Usage()
	}

	StaticFileServer = http.FileServer(http.Dir(filepath.Join(StoragePath, "files")))

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
			CacheDir:             filepath.Join(StoragePath, "ssl-certificates"),
			DNSProvider:          "",
			Local:                SelfSignedCertificate,
			UpdateHosts:          false,
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
			if err := http_server.ListenAndServe(); err != http.ErrServerClosed {
				log.Fatalf("HTTP ListenAndServe FAILED: %w", err)
			}
		}()
		go func() {
			if err := https_server.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
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
