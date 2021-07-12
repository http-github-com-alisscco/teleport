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
	"net"
	"strings"
	"sync"

	"github.com/gravitational/teleport/lib/tlsca"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"
	"github.com/sirupsen/logrus"
)

const (
	KubeSNIPrefix = "kube."
)

type Config struct {
	Listener  net.Listener
	TLSConfig *tls.Config
	Router    *Router
	Log       logrus.FieldLogger
}

func NewRouter() *Router {
	return &Router{
		alpnHandlers: make(map[string]*HandlerDecs),
	}
}

type Router struct {
	alpnHandlers       map[string]*HandlerDecs
	kubeHandler        *HandlerDecs
	databaseTLSHandler *HandlerDecs
	mtx                sync.Mutex
}

func (r *Router) AddKubeHandler(handler HandlerFunc) {
	r.mtx.Lock()
	defer r.mtx.Unlock()
	r.kubeHandler = &HandlerDecs{
		Handler:    handler,
		ForwardTLS: true,
	}
}
func (r *Router) AddDBTLSHandler(handler HandlerFunc) {
	r.mtx.Lock()
	defer r.mtx.Unlock()
	r.databaseTLSHandler = &HandlerDecs{
		Handler:    handler,
	}
}

func (r *Router) Add(desc HandlerDecs) {
	r.mtx.Lock()
	defer r.mtx.Unlock()
	for _, protocol := range desc.Protocols {
		r.alpnHandlers[protocol] = &desc
	}
}

type HandlerDecs struct {
	Name       string
	Protocols  []string
	Handler    HandlerFunc
	ForwardTLS bool
}

type HandlerFunc func(ctx context.Context, conn net.Conn) error

type Proxy struct {
	cfg                Config
	supportedProtocols []string
	log                logrus.FieldLogger
	cancel             context.CancelFunc
}

func (c *Config) CheckAndSetDefaults() error {
	if c.TLSConfig == nil {
		return trace.BadParameter("tls config missing")
	}
	if len(c.TLSConfig.Certificates) == 0 {
		return trace.BadParameter("missing certs")
	}

	if c.Listener == nil {
		return trace.BadParameter("listener missing")
	}
	if c.Log == nil {
		c.Log = logrus.WithField(trace.Component, "alpn:proxy")
	}
	return nil
}

func New(cfg Config) (*Proxy, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	var supportedProtocols []string
	for k := range cfg.Router.alpnHandlers {
		supportedProtocols = append(supportedProtocols, k)
	}
	return &Proxy{
		cfg:                cfg,
		log:                cfg.Log,
		supportedProtocols: supportedProtocols,
	}, nil
}

func (p *Proxy) Serve(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	p.cancel = cancel
	p.cfg.TLSConfig.NextProtos = p.supportedProtocols
	for {
		clientConn, err := p.cfg.Listener.Accept()
		if err != nil {
			if utils.IsOKNetworkError(err) {
				return nil
			}
			return trace.Wrap(err)
		}
		go func() {
			if err := p.handleConn(ctx, clientConn); err != nil {
				clientConn.Close()
				p.log.Warn("connection handling failed: ", err)
			}
		}()
	}
}

func (p *Proxy) handleConn(ctx context.Context, clientConn net.Conn) error {
	hello, conn, err := readHello(clientConn)
	if err != nil {
		return trace.Wrap(err)
	}

	handlerDesc, err := p.getHandlerDescBaseOnClientHelloMsg(hello)
	if err != nil {
		return trace.Wrap(err)
	}

	if !handlerDesc.ForwardTLS {
		tlsConn := tls.Server(conn, p.cfg.TLSConfig)
		if err := tlsConn.Handshake(); err != nil {
			return trace.Wrap(err)
		}
		conn = tlsConn
		if p.isDatabaseConnection(tlsConn.ConnectionState()) {
			if p.cfg.Router.databaseTLSHandler == nil {
				return trace.BadParameter("database handle not enabled")
			}
			return p.cfg.Router.databaseTLSHandler.Handler(ctx, conn)
		}
	}

	if err = handlerDesc.Handler(ctx, conn); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

func (p *Proxy) getHandlerDescBaseOnClientHelloMsg(clientHelloInfo *tls.ClientHelloInfo) (*HandlerDecs, error) {
	if shouldRouteToKubeService(clientHelloInfo.ServerName) {
		if p.cfg.Router.kubeHandler == nil {
			return nil, trace.BadParameter("received kube request but k8 service is disabled")
		}
		return p.cfg.Router.kubeHandler, nil
	}
	return p.getHandleDescBasedOnALPNVal(clientHelloInfo)
}

func (p *Proxy) getHandleDescBasedOnALPNVal(clientHelloInfo *tls.ClientHelloInfo) (*HandlerDecs, error) {
	protocol := ProtocolDefault
	if len(clientHelloInfo.SupportedProtos) != 0 {
		protocol = clientHelloInfo.SupportedProtos[0]
	}
	handlerDesc, ok := p.cfg.Router.alpnHandlers[protocol]
	if !ok {
		return nil, trace.BadParameter("unsupported ALPN protocol %q", protocol)
	}
	return handlerDesc, nil
}


func shouldRouteToKubeService(sni string) bool {
	return strings.HasPrefix(sni, KubeSNIPrefix)
}

func (p *Proxy) Close() error {
	p.cancel()
	if err := p.cfg.Listener.Close(); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

func (p *Proxy) isDatabaseConnection(state tls.ConnectionState) bool {
	// VerifiedChains must be populated after the handshake.
	if len(state.VerifiedChains) < 1 || len(state.VerifiedChains[0]) < 1 {
		return false
	}
	identity, err := tlsca.FromSubject(state.VerifiedChains[0][0].Subject,
		state.VerifiedChains[0][0].NotAfter)
	if err != nil {
		p.log.WithError(err).Debug("Failed to decode identity from client certificate.")
		return false
	}
	return identity.RouteToDatabase.ServiceName != ""
}
