package main

import (
	"errors"
	"regexp"
)

type endpoint struct {
	HostName string
	Addr string
	Port string
}

func LoadEndpoint(input string) (endpoint, error) {
	regexpattern := `^([a-z.A-Z]*)@?([a-z.A-Z\d]*):([\d]+)$`
	match, _ := regexp.MatchString(regexpattern, input)
	if !match {
		return endpoint{}, errors.New("invalid endpoint format for " + input)
	}
	result := regexp.MustCompile(regexpattern).FindStringSubmatch(input)
	HostName, Addr, Port := result[1], result[2], result[3]
	if Addr=="" {
		Addr=HostName
	}
	return endpoint{HostName:HostName,Addr:Addr,Port: Port}, nil
}

func (Endpoint endpoint) ToString() string {
	return Endpoint.HostName+"@"+Endpoint.Addr+":"+Endpoint.Port
}