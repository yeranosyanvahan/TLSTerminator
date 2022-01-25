package main

import (
	"crypto/tls"
	"fmt"
	"gopkg.in/ini.v1"
	"io"
	"log"
	"net"
	"os"
	"strings"
)

type Global struct {
	TLSIN  bool
	TLSOUT bool
}

var vproxies = map[string]map[string]*Proxy{}
var defaultproxy = Proxy{}
var global Global

const configfile = "/etc/tlsterm/tlsterm.ini"

func main() {
	cfg, err := ini.Load(configfile)
	if err != nil {
		fmt.Printf("Fail to read file: %v", err)
		os.Exit(1)
	}
	vhosts := cfg.SectionStrings()
	err = cfg.Section("").MapTo(&global)
	if err != nil {
		fmt.Println("Error while loading globals", err)
		os.Exit(1)
	}
	err = cfg.Section("").MapTo(&defaultproxy)
	if err != nil {
		fmt.Println("Error while loading globals", err)
		os.Exit(1)
	}
	err = defaultproxy.CheckSSL(global)
	if err != nil {
		fmt.Println("Error while loading default certs", err)
		os.Exit(1)
	}
	for _, host := range vhosts {
		if host == "DEFAULT" {
			continue
		}
		proxy, err := LoadProxy(host, cfg.Section(host))
		proxy.OVERWRITENULL(defaultproxy)
		err = proxy.CheckSSL(global)
		if err != nil {
			fmt.Println("Error while loading '"+host+"' certs", err)
			os.Exit(1)
		}
		if err != nil {
			fmt.Println("Error while loading config ::", err)
			os.Exit(1)
		}
		err = proxy.CheckConnection(global)
		if err != nil {
			fmt.Println("Couldn't connect to'"+proxy.OUT.ToString()+"'server ::", err)
		} else {
			log.Println("Successfully connected to '" + proxy.OUT.ToString() + "' host is ready")
		}
		vproxies[proxy.IN.Port] = make(map[string]*Proxy)
		vproxies[proxy.IN.Port][proxy.IN.HostName] = &proxy
	}
	for Port, _ := range vproxies {
		go ListenTo(Port)
	}
	for {
	}
}

func ListenTo(ListenAddr string) {
	log.Println("Listening to", ListenAddr)
	config := &tls.Config{GetCertificate: HandleCertificateIN}
	socket, err := tls.Listen("tcp", ":"+ListenAddr, config)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	defer socket.Close()
	for {
		conn, err := socket.Accept()
		if err != nil {
			log.Printf("Connection Accepting Error: %s", err)
			break
		}
		defer conn.Close()
		Raddr := conn.RemoteAddr().(*net.TCPAddr).String()
		Laddr := conn.LocalAddr().(*net.TCPAddr).String()
		if global.TLSIN {
			tlscon, ok := conn.(*tls.Conn)
			if ok {

				err := tlscon.Handshake()
				if err != nil {
					log.Printf("TLS handshake error %s", err)
					continue
				}
				state := tlscon.ConnectionState()
				ServerName := state.ServerName
				log.Println("Client connected: ", Raddr, "To", ServerName+"@"+Laddr)
				go HandleTLSConnection(ServerName, tlscon)
			}
		} else {
			log.Println("Client connected: ", Raddr, "To", Laddr)
			go HandleConnection(conn)
		}

	}
}

func HandleConnection(clientconn net.Conn) {
	defer clientconn.Close()
	Listen := strings.Split(clientconn.LocalAddr().String(), ":")
	Port := Listen[len(Listen)-1]

	if proxy, ok := vproxies[Port][""]; ok {
		if global.TLSOUT {
			config := &tls.Config{GetCertificate: HandleCertificateOUT, ServerName: proxy.OUT.HostName}
			serverconn, err := tls.Dial("tcp", proxy.OUT.Addr+":"+proxy.OUT.Port, config)
			if err != nil {
				log.Println("Couldn't connect to ", proxy.OUT.ToString())
				return
			}
			serverconn.Handshake()
			defer serverconn.Close()
			go ConnToConn(clientconn, serverconn)
			ConnToConn(serverconn, clientconn)
		} else {
			serverconn, err := net.Dial("tcp", proxy.OUT.Addr+":"+proxy.OUT.Port)
			if err != nil {
				log.Println("Couldn't connect to ", proxy.OUT.ToString())
				return
			}
			defer serverconn.Close()
			go ConnToConn(clientconn, serverconn)
			ConnToConn(serverconn, clientconn)

		}
	} else {
		log.Println("Couldn't find the host to connect to")
	}
}

func HandleTLSConnection(ServerName string, clientconn net.Conn) {
	defer clientconn.Close()
	Listen := strings.Split(clientconn.LocalAddr().String(), ":")
	Port := Listen[len(Listen)-1]

	if proxy, ok := vproxies[Port][ServerName]; ok {
		if global.TLSOUT {
			config := &tls.Config{GetCertificate: HandleCertificateOUT, ServerName: proxy.OUT.HostName}
			serverconn, err := tls.Dial("tcp", proxy.OUT.Addr, config)
			if err != nil {
				log.Println("Couldn't connect to ", proxy.OUT.ToString())
				return
			}
			serverconn.Handshake()
			defer serverconn.Close()
			go ConnToConn(clientconn, serverconn)
			ConnToConn(serverconn, clientconn)
		} else {
			serverconn, err := net.Dial("tcp", proxy.OUT.Addr)
			if err != nil {
				log.Println("Couldn't connect to ", proxy.OUT.ToString())
				return
			}
			defer serverconn.Close()
			go ConnToConn(clientconn, serverconn)
			ConnToConn(serverconn, clientconn)

		}
	} else {
		log.Println("Couldn't find the host to connect to")
	}
}

func ConnToConn(conn1, conn2 net.Conn) {
	n, err := io.Copy(conn1, conn2)
	log.Println("CTC n:", n)
	if err != nil {
		log.Println("CTC err:", err)
	}
}

func HandleCertificateIN(client *tls.ClientHelloInfo) (*tls.Certificate, error) {
	Listen := strings.Split(client.Conn.LocalAddr().String(), ":")
	Port := Listen[len(Listen)-1]
	if proxy, ok := vproxies[Port][client.ServerName]; ok {
		log.Println("Certificate Loaded for", "'"+client.ServerName+"'")
		cert, err := proxy.GETINCerts()
		return &cert, err
	} else {
		log.Println("General Certificate Loaded", "'"+client.ServerName+"'")
		cert, err := defaultproxy.GETINCerts()
		return &cert, err
	}
}
func HandleCertificateOUT(client *tls.ClientHelloInfo) (*tls.Certificate, error) {
	Listen := strings.Split(client.Conn.LocalAddr().String(), ":")
	Port := Listen[len(Listen)-1]
	if proxy, ok := vproxies[Port][client.ServerName]; ok {
		log.Println("Certificate Loaded for", "'"+client.ServerName+"'")
		cert, err := proxy.GETOUTCerts()
		return &cert, err
	} else {
		log.Println("General Certificate Loaded", "'"+client.ServerName+"'")
		cert, err := defaultproxy.GETOUTCerts()
		return &cert, err
	}

}
