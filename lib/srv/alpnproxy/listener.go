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
	"net"

	"github.com/gravitational/trace"
)

func NewListenerWrapper(listener net.Listener, tt net.Listener) *ListenerWrapper {
	return &ListenerWrapper{
		tt:       tt,
		Listener: listener,
		connC:    make(chan net.Conn),
		errC:     make(chan error),
		close:    make(chan struct{}),
	}
}

type ListenerWrapper struct {
	tt   net.Listener
	net.Listener
	connC chan net.Conn
	errC  chan error
	close chan struct{}
}

func (l *ListenerWrapper) Addr() net.Addr {
	if l.tt != nil {
		return l.tt.Addr()
	}
	return l.Listener.Addr()
}

func (l *ListenerWrapper) Accept() (net.Conn, error) {
	go l.startAcceptingConnectionFromListener()
	select {
	case <-l.close:
		return nil, trace.ConnectionProblem(nil, "closed")
	case err := <-l.errC:
		return nil, err
	case conn := <-l.connC:
		return conn, nil
	}
}

func (l *ListenerWrapper) startAcceptingConnectionFromListener() {
	if l.Listener == nil {
		return
	}
	for {
		select {
		case <-l.close:
			return
		default:
		}
		conn, err := l.Listener.Accept()
		if err != nil {
			l.errC <- err
			return
		}
		l.connC <- conn
	}
}

func (l *ListenerWrapper) HandleConnection(ctx context.Context, conn net.Conn) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case l.connC <- conn:
		return nil
	}
}

func (l *ListenerWrapper) Close() error {
	var errs []error
	if l.Listener != nil {
		if err := l.Listener.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if l.tt != nil {
		if err := l.tt.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	// Close channel only once
	select {
	case <-l.close:
	default:
		close(l.close)
	}
	return trace.NewAggregate(errs...)
}
