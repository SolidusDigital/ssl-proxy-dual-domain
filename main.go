package main

import (
	"flag"
	"fmt"
	"log"
	"net"
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
	to              = flag.String("to", "http://127.0.0.1:80", "the address and port for which to proxy requests to")
	fromURL         = flag.String("from", "127.0.0.1:443", "the tcp address and port this proxy should listen for requests on")
	certFile        = flag.String("cert", "", "path to a tls certificate file")
	keyFile         = flag.String("key", "", "path to a private key file")
	domains         = flag.String("domains", "", "comma-separated list of domains to mint letsencrypt certificates for")
	redirectHTTP    = flag.Bool("redirectHTTP", false, "if true, redirects http requests from port 80 to https at your fromURL")
	cacheDir        = flag.String("cacheDir", "certs", "directory to store cached certificates")
	domainMap       = flag.String("domainMap", "", "comma-separated list of domain=proxy mappings")
	ipFilterMap     = flag.String("ipFilterMap", "", "comma-separated list of domain=ip1|ip2|ip3 mappings")
	domainToProxyMap = map[string]string{}
	domainAllowedIPs = map[string][]string{}
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
				log.Printf("Mapping domain %s to proxy %s", parts[0], parts[1])
			} else {
				log.Fatalf("Invalid domain mapping: %s", mapping)
			}
		}
	}

	// Added debugging to ensure all IPs in the list are processed independently
	if *ipFilterMap != "" {
		mappings := strings.Split(*ipFilterMap, ",")
		for _, mapping := range mappings {
			parts := strings.SplitN(mapping, "=", 2)
			if len(parts) != 2 {
				log.Printf("Skipping invalid IP filter mapping: %s. Ensure it follows the format domain=ip1|ip2|ip3", mapping)
				continue
			}
			domain := parts[0]
			ips := strings.Split(parts[1], "|")
			log.Printf("Processing IP list for domain %s: %v", domain, ips)
			for i, ip := range ips {
				log.Printf("Processing IP: %s", ip)
				trimmedIP := strings.TrimSpace(strings.Trim(ip, "[]")) // Normalize IPv6
				log.Printf("Trimmed IP: %s", trimmedIP)
				parsedIP := net.ParseIP(trimmedIP)
				if parsedIP == nil {
					log.Fatalf("Invalid IP address: %s in mapping for domain %s", trimmedIP, domain)
				}
				log.Printf("Parsed IP: %s", parsedIP.String())
				ips[i] = trimmedIP
			}
			domainAllowedIPs[domain] = ips
			log.Printf("IP filter for %s: %v", domain, ips)
		}
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
	// Added debugging logs to trace IP filtering logic
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		log.Printf("Received request for host: %s", host)
		log.Printf("Remote address: %s", r.RemoteAddr)
		log.Printf("User-Agent: %s", r.Header.Get("User-Agent"))
		log.Printf("X-Forwarded-For: %s", r.Header.Get("X-Forwarded-For"))
		log.Printf("X-Real-IP: %s", r.Header.Get("X-Real-IP"))
		target, ok := domainToProxyMap[host]
		if !ok {
			log.Printf("No mapping found for host: %s", host)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// Apply IP filtering if defined
		if allowedIPs, exists := domainAllowedIPs[host]; exists {
			clientIP := getClientIP(r)
			log.Printf("Client IP for %s: %s", host, clientIP)
			log.Printf("Allowed IPs for %s: %v", host, allowedIPs)

			ipAllowed := false
			for _, allowed := range allowedIPs {
				log.Printf("Comparing client IP %s with allowed IP %s", clientIP, allowed)
				if net.ParseIP(clientIP).Equal(net.ParseIP(allowed)) { // Use net.ParseIP for accurate comparison
					ipAllowed = true
					break
				}
			}
			if !ipAllowed {
				log.Printf("Rejected connection from IP %s to host %s", clientIP, host)
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
		}

		targetURL, err := url.Parse(target)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		clientIP := getClientIP(r)
		log.Printf("Request URL: %s, Upstream Proxy URL: %s, Client IP: %s", r.URL.String(), targetURL.String(), clientIP)
		p := reverseproxy.Build(targetURL)
		p.ServeHTTP(w, r)
	})

	log.Printf(green("Proxying calls from https://%s (SSL/TLS) to respective endpoints based on domain"), *fromURL)

	// Redirect http requests on port 80 to TLS port using https
	if *redirectHTTP {
		go func() {
			redirectTLS := func(w http.ResponseWriter, r *http.Request) {
				host := r.Host
				_, ok := domainToProxyMap[host]
				if !ok {
					http.Error(w, "Forbidden", http.StatusForbidden)
					return
				}
				http.Redirect(w, r, "https://"+host+r.RequestURI, http.StatusMovedPermanently)
			}
			log.Println("Redirecting HTTP (port 80) to HTTPS")
			err := http.ListenAndServe(":80", http.HandlerFunc(redirectTLS))
			if err != nil {
				log.Println("HTTP redirection server error:", err)
			}
		}()
	}

	if validDomains {
		domainList := strings.Split(*domains, ",")
		log.Printf("Using LetsEncrypt for domains: %v", domainList)
		if (!strings.HasSuffix(*fromURL, ":443")) {
			log.Println("WARNING: LetsEncrypt typically requires port 443")
		}
		m := &autocert.Manager{
			Cache:      autocert.DirCache(*cacheDir),
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(domainList...),
		}
		s := &http.Server{
			Addr:      *fromURL,
			TLSConfig: m.TLSConfig(),
			Handler:   mux,
		}
		log.Fatal(s.ListenAndServeTLS("", ""))
	} else {
		log.Fatal(http.ListenAndServeTLS(*fromURL, *certFile, *keyFile, mux))
	}
}

// Updated getClientIP to normalize IPv6 addresses by removing square brackets
func getClientIP(r *http.Request) string {
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		parts := strings.Split(xff, ",")
		ip := strings.TrimSpace(parts[0])
		log.Printf("Extracted IP from X-Forwarded-For: %s", ip)
		return ip
	}
	ip := r.RemoteAddr
	if colon := strings.LastIndex(ip, ":"); colon != -1 {
		ip = ip[:colon]
	}
	log.Printf("Extracted IP from RemoteAddr: %s", ip)
	return ip
}

func green(in string) string {
	return fmt.Sprintf("\033[0;32m%s\033[0;0m", in)
}