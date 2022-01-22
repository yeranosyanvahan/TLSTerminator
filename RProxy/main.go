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
const configfile = "/etc/rproxy/rproxy.ini"
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
	config := &tls.Config{GetCertificate: HandleCertificates}
	socket, err := tls.Listen("tcp", ":"+strconv.Itoa(ListenPort), config)
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
      tlscon, ok := conn.(*tls.Conn)
      if ok {
          err := tlscon.Handshake()
          if(err!=nil){
            log.Printf("TLS handshake error %s", err); continue
          }
          state := tlscon.ConnectionState()
          ServerName := state.ServerName
          log.Println("New Connection:",ServerName+"@"+conn.RemoteAddr().String()+"/tcp")
          go HandleConnection(ServerName,tlscon)
          }

  }
}

func HandleCertificates(client *tls.ClientHelloInfo) (*tls.Certificate, error) {
    cert := vproxies["DEFAULT"].X509KeyPair
    return &cert, nil
}

func HandleConnection(ServerName string, clientconn net.Conn) {
  defer clientconn.Close()
  serverconn, err := net.Dial("tcp", vproxies["DEFAULT"].Redirect)
  if err != nil {
  	log.Println("Couldn't connect to",vproxies["DEFAULT"].Redirect);return
  }
  defer serverconn.Close()

  go ConnToConn(clientconn,serverconn)
  ConnToConn(serverconn,clientconn)

}
func ConnToConn(conn1,conn2 net.Conn) {
  buffer := make([]byte, 512)
  for {
      n, err := conn1.Read(buffer)
      if err != nil {
          log.Println("read error:", err); break
      }
      conn2.Write(buffer)
  }
}
// func ReadConnToChannel(conn, channel) {
//   buffer := make([]byte, buffersize)
//   for {
//       content, err := conn.Read(buffer)
//       if err != nil {
//           log.Println("read error:", err); break
//       }
//       channel <- buffer
//   }
// }
