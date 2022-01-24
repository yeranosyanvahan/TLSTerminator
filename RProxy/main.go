package main

import (
	"crypto/tls"
	"gopkg.in/ini.v1"
	"io"
	"log"
	"net"
	"os"
	"strconv"
)

type Proxy struct {
	Validate bool
    AllowIPs []net.IP
    Incoming endpoint
	Outgoing endpoint
}

var Listen int
var vproxies = map[int]map[string]Proxy{}

const configfile = "/etc/rproxy/rproxy.ini"

func main() {
	cfg, err := ini.Load(configfile)
	if err != nil {
		log.Printf("Fail to read file: %v", err)
		os.Exit(1)
	}
	Listen, err = cfg.Section("").Key("Listen").Int()
	if err != nil {
		log.Printf("Invalid Variable Listen: %v", err)
		os.Exit(1)
	}

	vhosts := cfg.SectionStrings()
	for _, ServerName := range vhosts {
		proxy := Proxy{ServerName: ServerName}
		err = cfg.Section(ServerName).MapTo(&proxy)
		if proxy.SSLCertificateFile != "" || proxy.SSLCertificateKeyFile != "" {
			certs, err := tls.LoadX509KeyPair(proxy.SSLCertificateFile, proxy.SSLCertificateKeyFile)
			if err != nil {
				log.Println("ERR", err)
				os.Exit(1)
			}
			proxy.X509KeyPair = certs
		}
		vproxies[ServerName] = proxy
	}
	ListenTo(Listen)
}

func ListenTo(ListenPort int) {
	log.Println("Listening to:", ListenPort)
	config := &tls.Config{GetCertificate: HandleCertificates, InsecureSkipVerify: true}
	socket, err := tls.Listen("tcp", ":"+strconv.Itoa(ListenPort), config)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	defer socket.Close()

	for {
		conn, err := socket.Accept()
		if err != nil {
			log.Printf("Accept Failure: %s", err)
			break
		}
		defer conn.Close()
		tlscon, ok := conn.(*tls.Conn)
		if ok {
			addr := conn.RemoteAddr().(*net.TCPAddr)
			err := tlscon.Handshake()
			if err != nil {
				log.Printf("TLS handshake error %s", err)
				continue
			}
			state := tlscon.ConnectionState()
			ServerName := state.ServerName
			log.Println("Client connected: ", ServerName+"@", addr)
			go HandleConnection(ServerName, tlscon)
		}

	}
}

func HandleCertificates(client *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert := vproxies["DEFAULT"].X509KeyPair
	return &cert, nil
}

func HandleConnection(ServerName string, clientconn net.Conn) {
	defer clientconn.Close()
	defaultredirect := vproxies["DEFAULT"].Redirect
	specialredirect := vproxies[ServerName].Redirect
	log.Println("Client connected: ", ServerName)
	var redirect string
	if specialredirect == "" {
		log.Println("Connecting To Default Redirect", defaultredirect)
		if defaultredirect == "" {
		}
		redirect = defaultredirect
	} else {
		log.Println("Connecting To Special Redirect", specialredirect)
		redirect = specialredirect
	}

	serverconn, err := net.Dial("tcp", redirect)
	if err != nil {
		log.Println("Couldn't connect to", redirect)
		return
	}
	defer serverconn.Close()

	go ConnToConn(clientconn, serverconn)
	ConnToConn(serverconn, clientconn)

}
func ConnToConn(conn1, conn2 net.Conn) {
	n, err := io.Copy(conn1, conn2)
	log.Println("CTC n:", n)
	if err != nil {
		log.Println("CTC err:", err)
	}
}
