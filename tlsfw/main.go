package main

import (
    "crypto/tls"
    "strings"
    "log"
		"os"
)

const SSLKEY = "../cert/server.key"
const SSLCRT = "../cert/server.crt"
const dialto = "test@10.2.3.54:234"
func main() {
  ServerName,IP := strings.Split(dialto, "@")
  config := &tls.Config{GetCertificate: HandleCertificates, InsecureSkipVerify: true, ServerName: "test"}
  serverconn, err := tls.Dial("tcp", "google.com:443", config)
  if(err!=nil){
    log.Println("Connection error",err)
  }
  serverconn.Handshake()
}

func HandleCertificates(client *tls.ClientHelloInfo) (*tls.Certificate, error) {
    certs, err := tls.LoadX509KeyPair(SSLCRT,SSLKEY)
    if err != nil {
      log.Println("ERR",err); os.Exit(1)
    }
    return &certs, nil
}
