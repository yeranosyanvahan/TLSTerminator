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
	"sync"
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
	if cfg.Section("").HasKey("Redirect") {
		defaultproxy, err = LoadProxy(":0", cfg.Section(""))
	} else {
		err = cfg.Section("").MapTo(&defaultproxy)
	}
	if err != nil {
		fmt.Println("Error while loading default host", err)
		os.Exit(1)
	}
	err = defaultproxy.CheckSSL(global)
	if err != nil {
		fmt.Println("Error while loading default certs", err)
		os.Exit(1)
	}
	fmt.Println("Loading and Checking configuration")
	var proxy Proxy
	for _, host := range vhosts {
		// Loading Configuration
		if host == "DEFAULT" {
			proxy = defaultproxy
		} else {
			proxy, err = LoadProxy(host, cfg.Section(host))
			if err != nil {
				fmt.Println("Error while loading config for '"+host+"'::", err)
				os.Exit(1)
			}
			proxy.OVERWRITENULL(defaultproxy)
			vproxies[proxy.IN.Port] = make(map[string]*Proxy)
			vproxies[proxy.IN.Port][proxy.IN.HostName] = &proxy
		}
		//Checking configuration
		err = proxy.CheckSSL(global)
		if err != nil {
			fmt.Println("Error while loading '"+host+"' certs", err)
			os.Exit(1)
		}
		err = proxy.CheckConnection(global)
		if err != nil {
			fmt.Println("Couldn't connect to'"+proxy.OUT.ToString()+"'server ::", err)
		} else {
			log.Println("Successfully connected to '" + proxy.OUT.ToString() + "' host is ready")
		}
	}
	for Port, _ := range vproxies {
		go ListenTo(Port)
	}
	for {
	}
}

func ListenTo(ListenAddr string) {
	log.Println("Listening to", ListenAddr)
	var socket net.Listener
	var err error
	if global.TLSIN {
		config := &tls.Config{GetCertificate: HandleCertificateIN, InsecureSkipVerify: true}
		socket, err = tls.Listen("tcp", ":"+ListenAddr, config)
	} else {
		socket, err = net.Listen("tcp", ":"+ListenAddr)
	}

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
				go HandleConnection(ServerName, tlscon)
			}
		} else {
			log.Println("Client connected: ", Raddr, "To", Laddr)
			go HandleConnection("", conn)
		}

	}
}

func HandleConnection(ServerName string, clientconn net.Conn) {
	defer clientconn.Close()
	Listen := strings.Split(clientconn.LocalAddr().String(), ":")
	Port := Listen[len(Listen)-1]

	var proxy *Proxy
	if pseudoproxy, ok := vproxies[Port][ServerName]; ok {
		proxy = pseudoproxy
		log.Println("Found redirect for this host:", proxy.OUT.ToString())
	} else {
		proxy = &defaultproxy
		if proxy.OUT.Port == "" {
			log.Println("Could't Find redirect for this host, and no default redirect is found:")
			return
		}
		log.Println("Could't Find redirect for this host, trying default redirect:", proxy.OUT.ToString())
	}

	if global.TLSOUT {
		config := &tls.Config{GetCertificate: HandleCertificateOUT, ServerName: proxy.OUT.HostName, InsecureSkipVerify: true}
		serverconn, err := tls.Dial("tcp", proxy.OUT.Addr+":"+proxy.OUT.Port, config)
		if err != nil {
			log.Println("Couldn't connect to ", proxy.OUT.ToString(), err)
			return
		}
		serverconn.Handshake()
		defer serverconn.Close()
		ConnToConn(clientconn, serverconn)

	} else {
		serverconn, err := net.Dial("tcp", proxy.OUT.Addr+":"+proxy.OUT.Port)
		if err != nil {
			log.Println("Couldn't connect to ", proxy.OUT.ToString(), err)
			return
		}
		defer serverconn.Close()
		ConnToConn(clientconn, serverconn)

	}
}

var numConnections int = 0

func ConnToConn(IN, OUT net.Conn) {
	numConnections += 1
	log.Println("!!Connected!! Number of Connection: ", numConnections)
	defer func() { numConnections -= 1; log.Println("!!DisConnected!! Number of Connection: ", numConnections) }()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		io.Copy(IN, OUT)
		if TLSIN, ok := IN.(*tls.Conn); ok {
			TLSIN.CloseWrite()
		} else {
			IN.(*net.TCPConn).CloseWrite()
		}
		wg.Done()
	}()
	go func() {
		io.Copy(OUT, IN)
		if TLSOUT, ok := OUT.(*tls.Conn); ok {
			TLSOUT.CloseWrite()
		} else {
			OUT.(*net.TCPConn).CloseWrite()
		}
		wg.Done()
	}()
	wg.Wait()
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
