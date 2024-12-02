package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/suyashkumar/ssl-proxy/gen"
	"github.com/suyashkumar/ssl-proxy/reverseproxy"
	"golang.org/x/crypto/acme/autocert"
)

var (
	to           = flag.String("to", "http://127.0.0.1:80", "the address and port for which to proxy requests to")
	fromURL      = flag.String("from", "127.0.0.1:443", "the tcp address and port this proxy should listen for requests on")
	certFile     = flag.String("cert", "", "path to a tls certificate file. If not provided, ssl-proxy will generate one for you in ~/.ssl-proxy/")
	keyFile      = flag.String("key", "", "path to a private key file. If not provided, ssl-proxy will generate one for you in ~/.ssl-proxy/")
	domains      = flag.String("domains", "", "comma-separated list of domains to mint letsencrypt certificates for. Usage of this parameter implies acceptance of the LetsEncrypt terms of service.")
	redirectHTTP = flag.Bool("redirectHTTP", false, "if true, redirects http requests from port 80 to https at your fromURL")
	cacheDir     = flag.String("cacheDir", "certs", "directory to store cached certificates") // Define the cacheDir flag
	domainMap    = flag.String("domainMap", "", "comma-separated list of domain=proxy mappings (e.g., example1.com=http://127.0.0.1:8081,example2.com=http://127.0.0.1:8082)")
	domainToProxyMap = map[string]string{
		"example1.com": "http://127.0.0.1:8081",
		"example2.com": "http://127.0.0.1:8082",
	}
)

const (
	DefaultCertFile = "cert.pem"
	DefaultKeyFile  = "key.pem"
	HTTPSPrefix     = "https://"
	HTTPPrefix      = "http://"
)

func main() {
	flag.Parse()

	// Parse domain-to-proxy mappings
	if *domainMap != "" {
		mappings := strings.Split(*domainMap, ",")
		for _, mapping := range mappings {
			parts := strings.Split(mapping, "=")
			if len(parts) == 2 {
				domainToProxyMap[parts[0]] = parts[1]
			} else {
				log.Fatalf("Invalid domain mapping: %s", mapping)
			}
		}
	}

	// Print the domain map
	log.Println("Domain to Proxy Map:")
	for domain, proxy := range domainToProxyMap {
		log.Printf("  %s -> %s\n", domain, proxy)
	}

	validCertFile := *certFile != ""
	validKeyFile := *keyFile != ""
	validDomains := *domains != ""

	// Determine if we need to generate self-signed certs
	if (!validCertFile || !validKeyFile) && !validDomains {
		// Use default file paths
		*certFile = DefaultCertFile
		*keyFile = DefaultKeyFile

		log.Printf("No existing cert or key specified, generating some self-signed certs for use (%s, %s)\n", *certFile, *keyFile)

		// Generate new keys
		certBuf, keyBuf, fingerprint, err := gen.Keys(365 * 24 * time.Hour)
		if err != nil {
			log.Fatal("Error generating default keys", err)
		}

		certOut, err := os.Create(*certFile)
		if err != nil {
			log.Fatal("Unable to create cert file", err)
		}
		certOut.Write(certBuf.Bytes())

		keyOut, err := os.OpenFile(*keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			log.Fatal("Unable to create the key file", err)
		}
		keyOut.Write(keyBuf.Bytes())

		log.Printf("SHA256 Fingerprint: % X", fingerprint)
	}

	// Ensure the to URL is in the right form
	if !strings.HasPrefix(*to, HTTPPrefix) && !strings.HasPrefix(*to, HTTPSPrefix) {
		*to = HTTPPrefix + *to
		log.Println("Assuming -to URL is using http://")
	}

	// Setup reverse proxy ServeMux
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		target, ok := domainToProxyMap[host]
		if !ok {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		targetURL, err := url.Parse(target)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		p := reverseproxy.Build(targetURL)
		p.ServeHTTP(w, r)
	})

	log.Printf(green("Proxying calls from https://%s (SSL/TLS) to respective endpoints based on domain"), *fromURL)

	// Redirect http requests on port 80 to TLS port using https
	if *redirectHTTP {
		go func() {
			redirectTLS := func(w http.ResponseWriter, r *http.Request) {
				host := r.Host
				redirectURL, ok := domainToProxyMap[host]
				if !ok {
					http.Error(w, "Forbidden", http.StatusForbidden)
					return
				}
				http.Redirect(w, r, "https://"+host+r.RequestURI, http.StatusMovedPermanently)
			}
			log.Println("Also redirecting http requests on port 80 to https requests based on domain mapping")
			err := http.ListenAndServe(":80", http.HandlerFunc(redirectTLS))
			if err != nil {
				log.Println("HTTP redirection server failure")
				log.Println(err)
			}
		}()
	}

	// Determine if we should serve over TLS with autogenerated LetsEncrypt certificates or not
	if validDomains {
		// Domain is present, use autocert
		// TODO: validate domain (though, autocert may do this)
		// TODO: for some reason this seems to only work on :443
		domainList := strings.Split(*domains, ",")
		log.Printf("Domains specified, using LetsEncrypt to autogenerate and serve certs for %v\n", domainList)
		if !strings.HasSuffix(*fromURL, ":443") {
			log.Println("WARN: Right now, you must serve on port :443 to use autogenerated LetsEncrypt certs using the -domains flag, this may NOT WORK")
		}
		m := &autocert.Manager{
			Cache:      autocert.DirCache(*cacheDir), // Use the cacheDir flag here
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(domainList...),
		}
		s := &http.Server{
			Addr:      *fromURL,
			TLSConfig: m.TLSConfig(),
		}
		s.Handler = mux
		log.Fatal(s.ListenAndServeTLS("", ""))
	} else {
		// Domain is not provided, serve TLS using provided/generated certificate files
		log.Fatal(http.ListenAndServeTLS(*fromURL, *certFile, *keyFile, mux))
	}
}

// green takes an input string and returns it with the proper ANSI escape codes to render it green-colored
// in a supported terminal.
// TODO: if more colors used in the future, generalize or pull in an external pkg
func green(in string) string {
	return fmt.Sprintf("\033[0;32m%s\033[0;0m", in)
}
