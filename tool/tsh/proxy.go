package main

import (
	"context"
	"fmt"
	"net"

	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/lib/srv/alpnproxy"
)

func onProxyCommandSSH(cf *CLIConf) error {
	client, err := makeClient(cf, false)
	if err != nil {
		return trace.Wrap(err)
	}

	lp := alpnproxy.NewLocalProxy(alpnproxy.LocalProxyConfig{
		RemoteProxyAddr:    client.WebProxyAddr,
		Protocol:           alpnproxy.ProtocolProxySSH,
		User:               cf.Username,
		UserHost:           cf.UserHost,
		HostKeyCallback:    client.HostKeyCallback,
		InsecureSkipVerify: cf.InsecureSkipVerify,
	})
	defer lp.Close()
	if err := lp.SSHProxy(cf.Context); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

func onProxyCommandDB(cf *CLIConf) error {
	client, err := makeClient(cf, false)
	if err != nil {
		return trace.Wrap(err)
	}
	database, err := pickActiveDatabase(cf)
	if err != nil {
		return trace.Wrap(err)

	}

	port := ":0"
	if cf.LocalProxyPort != "" {
		port = fmt.Sprintf(":%s", cf.LocalProxyPort)
	}
	listener, err := net.Listen("tcp", port)
	if err != nil {
		return trace.Wrap(err)
	}
	lp, err := mkLocalProxy(cf.Context, client.WebProxyAddr, database.Protocol, listener)
	if err != nil {
		return trace.Wrap(err)
	}
	ctx, cancel := context.WithCancel(cf.Context)
	defer cancel()
	go func() {
		<-ctx.Done()
		lp.Close()
	}()

	fmt.Printf("Started DB proxy on %q\n", listener.Addr())

	defer lp.Close()
	if err := lp.Start(cf.Context); err != nil {
		return trace.Wrap(err)
	}
	return nil
}
