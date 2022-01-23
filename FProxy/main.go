package main

import (
    "gopkg.in/ini.v1"
    "crypto/tls"
    "strconv"
    "log"
		"os"
    "net"
)
type Proxy struct {
    ServerName string
   	Redirect string
	  SSLCertificateKeyFile string
		SSLCertificateFile string
    X509KeyPair tls.Certificate
}

var Listen int
var vproxies = map[string]Proxy{}
const configfile = "/etc/fproxy/fproxy.ini"
func main() {
    cfg, err := ini.Load(configfile)
    if err != nil {
        log.Printf("Fail to read file: %v", err);  os.Exit(1)
    }
		Listen, err =  cfg.Section("").Key("Listen").Int()
    if err != nil {
        log.Printf("Invalid Variable Listen: %v", err);  os.Exit(1)
    }

		vhosts := cfg.SectionStrings()
    for _,ServerName := range vhosts {
			proxy := Proxy{ServerName: ServerName }
      err = cfg.Section(ServerName).MapTo(&proxy)
      if proxy.SSLCertificateFile!="" || proxy.SSLCertificateKeyFile!="" {
        certs, err := tls.LoadX509KeyPair(proxy.SSLCertificateFile, proxy.SSLCertificateKeyFile)
        if err != nil {
      		log.Println("ERR",err); os.Exit(1)
      	}
        proxy.X509KeyPair=certs
      }
      vproxies[ServerName]=proxy
		}

    ListenTo(Listen)
		os.Exit(3)
}

func ListenTo(ListenPort int) {
  log.Println("Listening to:",ListenPort)
	socket, err := net.Listen("tcp", ":"+strconv.Itoa(ListenPort))
	if err != nil {
		log.Println(err); os.Exit(1)
	}
  defer socket.Close()

  for {
      conn, err := socket.Accept()
      if err != nil {
          log.Printf("Accept Failure: %s", err); break
      }
      defer conn.Close()
      log.Println("New Connection:","@"+conn.RemoteAddr().String()+"/tcp")
      go HandleConnection(conn)
  }
}

func HandleCertificates(client *tls.ClientHelloInfo) (*tls.Certificate, error) {
    cert := vproxies["DEFAULT"].X509KeyPair
    return &cert, nil
}

func HandleConnection(clientconn net.Conn) {
  defer clientconn.Close()
  config := &tls.Config{GetCertificate: HandleCertificates, InsecureSkipVerify: true}
  serverconn, err := tls.Dial("tcp", vproxies["DEFAULT"].Redirect, config)
  if err != nil {
  	log.Println("Couldn't connect to",vproxies["DEFAULT"].Redirect);return
  }
  serverconn.Handshake()
  defer serverconn.Close()

  go ConnToConn(clientconn,serverconn)
  ConnToConn(serverconn,clientconn)

}
func ConnToConn(conn1,conn2 net.Conn) {
  buffer := make([]byte, 512)
  for {
      n, err := conn1.Read(buffer)
      log.Println("n:", n);
      log.Println("buffer:", string(buffer[:]));
      if err != nil {
          log.Println("Read error:", err);
          break
      }
      conn2.Write(buffer)
  }
}
