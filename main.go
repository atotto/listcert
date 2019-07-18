package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"github.com/mattn/go-zglob"
)

func main() {
	flag.Parse()
	dir := flag.Arg(0)
	matches, err := zglob.Glob(filepath.Join(dir, "/**/*"))
	if err != nil {
		log.Fatal(err)
	}

	for _, p := range matches {
		fi, err := os.Stat(p)
		if err != nil {
			continue
		}
		if fi.IsDir() {
			continue
		}
		cert, err := loadCertificates(p)
		if err != nil {
			log.Printf("failed to load certificate %s: %s", p, err)
			continue
		}
		var rp string
		pp := p
		for {
			rp, err = os.Readlink(pp)
			if err != nil {
				rp = pp
				break
			}
			pp = rp
		}
		if _, err := os.Stat(rp); os.IsNotExist(err) {
			continue
		}

		fmt.Printf("%s, %s, %s\n", rp, cert.Subject.CommonName, cert.NotAfter.Format("2006-01-02 15:04:05"))
	}
}

func loadCertificates(path string) (*x509.Certificate, error) {
	buf, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(buf)
	if block == nil {
		return nil, fmt.Errorf("failed to parse certificate PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}
