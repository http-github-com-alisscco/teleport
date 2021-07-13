/*
Copyright 2020-2021 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package alpnproxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/gravitational/trace"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/utils/agentconn"
)

type Protocol string

const (
	ProtocolPostgres      = "teleport-postgres"
	ProtocolMySQL         = "teleport-mysql"
	ProtocolMongoDB       = "teleport-mongodb"
	ProtocolProxySSH      = "teleport-proxy-ssh"
	ProtocolReverseTunnel = "teleport-reversetunnel"
	ProtocolHTTP          = "http/1.1"
	ProtocolHTTP2         = "h2"
	ProtocolDefault       = ""
)

type LocalProxyConfig struct {
	RemoveProxyAddr string
	//ListenerAddr       string
	Protocol           Protocol
	User               string
	UserHost           string
	HostKeyCallback    ssh.HostKeyCallback
	InsecureSkipVerify bool
	Listener           net.Listener
}

type LocalProxy struct {
	cfg   LocalProxyConfig
	close chan struct{}
}

func NewLocalProxy(cfg LocalProxyConfig) *LocalProxy {
	return &LocalProxy{
		cfg:   cfg,
		close: make(chan struct{}),
	}
}

func GetAgent() (agent.ExtendedAgent, error) {
	conn, err := agentconn.Dial(os.Getenv(teleport.SSHAuthSock))
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return agent.NewClient(conn), nil
}

func (l *LocalProxy) SSHProxy(ctx context.Context) error {
	upstreamConn, err := tls.Dial("tcp", l.cfg.RemoveProxyAddr, &tls.Config{
		NextProtos:         []string{string(l.cfg.Protocol)},
		InsecureSkipVerify: l.cfg.InsecureSkipVerify,
	})
	if err != nil {
		return trace.Wrap(err)
	}
	defer upstreamConn.Close()

	sshAgent, err := GetAgent()
	if err != nil {
		return trace.Wrap(err)
	}
	client, err := makeSSHClient(upstreamConn, l.cfg.RemoveProxyAddr, &ssh.ClientConfig{
		User: l.cfg.User,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeysCallback(sshAgent.Signers),
		},
		HostKeyCallback: l.cfg.HostKeyCallback,
	})
	if err != nil {
		return trace.Wrap(err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		return trace.Wrap(err)
	}
	defer sess.Close()

	err = agent.ForwardToAgent(client, sshAgent)
	if err != nil {
		return trace.Wrap(err)
	}
	err = agent.RequestAgentForwarding(sess)
	if err != nil {
		return trace.Wrap(err)
	}

	if err = sess.RequestSubsystem(proxySubsystemName(l.cfg.UserHost)); err != nil {
		return trace.Wrap(err)
	}
	if err := proxySession(ctx, sess); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

func proxySubsystemName(userHost string) string {
	return fmt.Sprintf("proxy:%s", userHost)
}

func makeSSHClient(conn *tls.Conn, addr string, cfg *ssh.ClientConfig) (*ssh.Client, error) {
	cc, chs, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return ssh.NewClient(cc, chs, reqs), nil
}

func proxySession(ctx context.Context, sess *ssh.Session) error {
	stdout, err := sess.StdoutPipe()
	if err != nil {
		return trace.Wrap(err)
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		return trace.Wrap(err)
	}
	stderr, err := sess.StderrPipe()
	if err != nil {
		return trace.Wrap(err)
	}

	errC := make(chan error)
	go func() {
		_, err := io.Copy(os.Stdout, stdout)
		errC <- err
	}()
	go func() {
		_, err := io.Copy(stdin, os.Stdin)
		errC <- err
	}()
	go func() {
		_, err := io.Copy(os.Stderr, stderr)
		errC <- err
	}()
	var errs []error
	for i := 0; i < 3; i++ {
		select {
		case <-ctx.Done():
			return nil
		case err := <-errC:
			if err != nil && !errors.Is(err, io.EOF) {
				errs = append(errs, err)
			}
		}
	}
	return trace.NewAggregate(errs...)
}

func (l *LocalProxy) Start(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-l.close:
			return nil
		default:
		}

		conn, err := l.cfg.Listener.Accept()
		if err != nil {
			log.Errorf("faield to accept client connection: %v\n", err)
			continue
		}
		go func() {
			if err := l.handleDownstreamConnection(ctx, conn); err != nil {
				log.Errorf("failed to handle connection: %v", err)
			}
		}()
	}
}

func (l *LocalProxy) GetAddr() string {
	return l.cfg.Listener.Addr().String()
}

func (l *LocalProxy) handleDownstreamConnection(ctx context.Context, downstreamConn net.Conn) error {
	defer downstreamConn.Close()
	upstreamConn, err := tls.Dial("tcp", l.cfg.RemoveProxyAddr, &tls.Config{
		NextProtos:         []string{string(l.cfg.Protocol)},
		InsecureSkipVerify: l.cfg.InsecureSkipVerify,
	})

	if err != nil {
		return trace.Wrap(err)
	}
	defer upstreamConn.Close()

	errC := make(chan error)
	go func() {
		_, err := io.Copy(downstreamConn, upstreamConn)
		errC <- err
	}()
	go func() {
		_, err := io.Copy(upstreamConn, downstreamConn)
		errC <- err
	}()

	var errs []error
	for i := 0; i < 2; i++ {
		select {
		case <-ctx.Done():
			return nil
		case <-l.close:
			return nil
		case err := <-errC:
			if err != nil && !errors.Is(err, io.EOF) {
				errs = append(errs, err)
			}
		}
	}
	return trace.NewAggregate(errs...)
}

func (l *LocalProxy) Close() {
	select {
	case _, ok := <-l.close:
		if !ok {
			return
		}
	default:
	}
	close(l.close)
	if l.cfg.Listener != nil {
		l.cfg.Listener.Close()
	}
}
