package main

import (
	"crypto/tls"
	"errors"
	"gopkg.in/ini.v1"
	"net"
)

type Proxy struct {
	Validate      bool
	AllowIPs      []net.IP
	IN            endpoint
	OUT           endpoint
	Redirect      string
	SSLCRTOUTFILE string
	SSLKEYOUTFILE string
	SSLCRTINFILE  string
	SSLKEYINFILE  string
}

func LoadProxy(host string, section *ini.Section) (Proxy, error) {
	proxy := Proxy{}
	err := section.MapTo(&proxy)
	if err != nil {
		return proxy, errors.New("Error while loading hostname " + err.Error())
	}
	EndpointIN, err := LoadEndpoint(host)
	if err != nil {
		return proxy, err
	}
	EndpointOUT, err := LoadEndpoint(proxy.Redirect)
	if err != nil {
		return proxy, err
	}
	if err != nil {
		return proxy, errors.New(host + " Loading Certificate Error " + err.Error())
	}
	proxy.IN = EndpointIN
	proxy.OUT = EndpointOUT

	return proxy, nil
}

func (proxy Proxy) GETINCerts() (tls.Certificate, error) {
	return tls.LoadX509KeyPair(proxy.SSLCRTINFILE, proxy.SSLKEYINFILE)
}
func (proxy Proxy) GETOUTCerts() (tls.Certificate, error) {
	return tls.LoadX509KeyPair(proxy.SSLCRTOUTFILE, proxy.SSLKEYOUTFILE)
}
func (proxy Proxy) CheckSSL(globals Global) error {
	if globals.TLSIN {
		_, err := proxy.GETINCerts()
		if err != nil {
			return err
		}
	}
	if globals.TLSIN {
		_, err := proxy.GETINCerts()
		if err != nil {
			return err
		}
	}
	return nil

}
func (proxy *Proxy) OVERWRITENULL(defaultproxy Proxy) {
	if proxy.SSLCRTOUTFILE == "" {
		proxy.SSLCRTOUTFILE = defaultproxy.SSLCRTOUTFILE
	}
	if proxy.SSLKEYOUTFILE == "" {
		proxy.SSLKEYOUTFILE = defaultproxy.SSLKEYOUTFILE
	}
	if proxy.SSLCRTINFILE == "" {
		proxy.SSLCRTINFILE = defaultproxy.SSLCRTINFILE
	}
	if proxy.SSLKEYINFILE == "" {
		proxy.SSLKEYINFILE = defaultproxy.SSLKEYINFILE
	}
	if proxy.Redirect == "" {
		proxy.Redirect = defaultproxy.Redirect
	}
}

func (proxy *Proxy) CheckConnection(globals Global) error {

	if global.TLSOUT {
		config := &tls.Config{GetCertificate: HandleCertificateOUT, ServerName: proxy.OUT.HostName}
		serverconn, err := tls.Dial("tcp", proxy.OUT.Addr+":"+proxy.OUT.Port, config)
		if err == nil {
			err = serverconn.Handshake()
			if err == nil {
				serverconn.Close()
			}
			return err
		}
		return err
	} else {
		serverconn, err := net.Dial("tcp", proxy.OUT.Addr+":"+proxy.OUT.Port)
		if err == nil {
			serverconn.Close()
		}
		return err
	}
}
