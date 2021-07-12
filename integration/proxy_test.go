/*
Copyright 2016-2021 Gravitational, Inc.

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

package integration

import (
	"context"
	"net"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib"
	"github.com/gravitational/teleport/lib/service"
	"github.com/gravitational/teleport/lib/srv/alpnproxy"
	"github.com/gravitational/teleport/lib/srv/db/common"
	"github.com/gravitational/teleport/lib/srv/db/postgres"
	"github.com/gravitational/teleport/lib/tlsca"
)

func TestNewProxy(t *testing.T) {
	testCase := []struct {
		name                   string
		mainClusterPortSetup   *InstancePorts
		secondClusterPortSetup *InstancePorts
	}{
		{
			mainClusterPortSetup:   standardPortSetup(),
			secondClusterPortSetup: oneProxyPortSetup(),
		},
		{
			mainClusterPortSetup:   oneProxyPortSetup(),
			secondClusterPortSetup: oneProxyPortSetup(),
		},
		{
			mainClusterPortSetup:   oneProxyPortSetup(),
			secondClusterPortSetup: standardPortSetup(),
		},
	}

	for _, tc := range testCase {
		t.Run(tc.name, func(t *testing.T) {
			lib.SetInsecureDevMode(true)
			defer lib.SetInsecureDevMode(false)

			username := mustGetCurrentUser(t).Username

			suite := newProxySuite(t,
				withMainConfig(mainStandardConfig(t)),
				withSecondConfig(mainSecondConfig(t)),
				withMainClusterPorts(standardPortSetup()),
				withSecondClusterPorts(oneProxyPortSetup()),
				withMainAndSecondClusterRoles(createAdminRole(username)),
				withStandardRoleMapping(),
			)
			// Run command in root.
			suite.mustConnectToClusterAndRunSSHCommand(t, ClientConfig{
				Login:   username,
				Cluster: suite.main.Secrets.SiteName,
				Host:    Loopback,
				Port:    suite.main.GetPortSSHInt(),
			})
			// Run command in leaf.
			suite.mustConnectToClusterAndRunSSHCommand(t, ClientConfig{
				Login:   username,
				Cluster: suite.second.Secrets.SiteName,
				Host:    Loopback,
				Port:    suite.second.GetPortSSHInt(),
			})
		})
	}
}

func TestNewProxyTunnel(t *testing.T) {
	lib.SetInsecureDevMode(true)
	defer lib.SetInsecureDevMode(false)

	username := mustGetCurrentUser(t).Username

	suite := newProxySuite(t,
		withMainConfig(mainStandardConfig(t)),
		withSecondConfig(mainSecondConfig(t)),
		withMainClusterRoles(newRole(t, "maindevs", username)),
		withSecondClusterRoles(newRole(t, "auxdevs", username)),
		withMainAndSecondTrustedClusterReset(),
		withTrustedCluster(),
	)

	nodeHostname := "clusterauxnode"
	suite.addNodeToSecondCluster(t, "clusterauxnode")

	// Try and connect to a node in the Aux cluster from the Main cluster using
	// direct dialing.
	suite.mustConnectToClusterAndRunSSHCommand(t, ClientConfig{
		Login:   username,
		Cluster: suite.second.Secrets.SiteName,
		Host:    Loopback,
		Port:    suite.second.GetPortSSHInt(),
	})

	// Try and connect to a node in the Aux cluster from the Main cluster using
	// tunnel dialing.
	suite.mustConnectToClusterAndRunSSHCommand(t, ClientConfig{
		Login:   username,
		Cluster: suite.second.Secrets.SiteName,
		Host:    nodeHostname,
	})
}

func TestNewProxyKube(t *testing.T) {
	const (
		localK8SNI = "kube.teleport.cluster.local"
		k8User     = "alice@example.com"
		k8RoleName = "kubemaster"
	)

	kubeAPIMockSvr := startKubeAPIMock(t)
	kubeConfigPath := mustCreateKubeConfigFile(t, k8ClientConfig(kubeAPIMockSvr.URL, localK8SNI))

	username := mustGetCurrentUser(t).Username
	kubeRoleSpec := types.RoleSpecV4{
		Allow: types.RoleConditions{
			Logins:     []string{username},
			KubeGroups: []string{testImpersonationGroup},
			KubeUsers:  []string{k8User},
		},
	}
	kubeRole, err := types.NewRole(k8RoleName, kubeRoleSpec)
	require.NoError(t, err)

	suite := newProxySuite(t,
		withMainConfig(mainStandardConfig(t), func(config *service.Config) {
			config.Proxy.Kube.Enabled = true
			config.Proxy.Kube.KubeconfigPath = kubeConfigPath
			config.Proxy.Kube.LegacyKubeProxy = true
		}),
		withSecondConfig(mainSecondConfig(t)),
		withMainAndSecondClusterRoles(kubeRole),
		withStandardRoleMapping(),
	)

	k8Client, _, err := kubeProxyClient(kubeProxyConfig{
		t:                   suite.main,
		username:            kubeRoleSpec.Allow.Logins[0],
		kubeUsers:           kubeRoleSpec.Allow.KubeGroups,
		kubeGroups:          kubeRoleSpec.Allow.KubeUsers,
		customTLSServerName: localK8SNI,
		targetAddress:       suite.main.Config.Proxy.WebAddr,
	})
	require.NoError(t, err)

	resp, err := k8Client.CoreV1().Pods("default").List(context.Background(), metav1.ListOptions{})
	require.NoError(t, err)
	require.Equal(t, 1, len(resp.Items), "pods item length mismatch")
}

func TestProxyDatabaseAccessProxySSNIDatabaseAccessPostgresRootClusterSNIProxy(t *testing.T) {
	pack := setupDatabaseTest(t,
		withPortSetupDatabaseTest(oneProxyPortSetup),
	)
	listener, err := net.Listen("tcp", ":0")
	require.NoError(t, err)

	lp := alpnproxy.NewLocalProxy(alpnproxy.LocalProxyConfig{
		RemoveProxyAddr:    pack.root.cluster.GetProxyAddr(),
		Protocol:           alpnproxy.ProtocolPostgres,
		InsecureSkipVerify: true,
		Listener:           listener,
	})
	defer lp.Close()

	sync := make(chan struct{})
	go func() {
		close(sync)
		err := lp.Start(context.Background())
		require.NoError(t, err)
	}()

	//TODO(smallinksy) get ready state from local proxy.
	<-sync

	t.Run("connect to main cluster via proxy", func(t *testing.T) {
		// Connect to the database service in root cluster.
		client, err := postgres.MakeTestClient(context.Background(), common.TestClientConfig{
			AuthClient: pack.root.cluster.GetSiteAPI(pack.root.cluster.Secrets.SiteName),
			AuthServer: pack.root.cluster.Process.GetAuthServer(),
			Address:    lp.GetAddr(),
			Cluster:    pack.root.cluster.Secrets.SiteName,
			Username:   pack.root.user.GetName(),
			RouteToDatabase: tlsca.RouteToDatabase{
				ServiceName: pack.root.postgresService.Name,
				Protocol:    pack.root.postgresService.Protocol,
				Username:    "postgres",
				Database:    "test",
			},
		})
		require.NoError(t, err)
		mustRunPostgresQuery(t, client)
		mustClosePostgresClient(t, client)
	})

	t.Run("connect to leaf cluster via proxy", func(t *testing.T) {
		client, err := postgres.MakeTestClient(context.Background(), common.TestClientConfig{
			AuthClient: pack.root.cluster.GetSiteAPI(pack.root.cluster.Secrets.SiteName),
			AuthServer: pack.root.cluster.Process.GetAuthServer(),
			Address:    lp.GetAddr(), // Connecting via root cluster.
			Cluster:    pack.leaf.cluster.Secrets.SiteName,
			Username:   pack.root.user.GetName(),
			RouteToDatabase: tlsca.RouteToDatabase{
				ServiceName: pack.leaf.postgresService.Name,
				Protocol:    pack.leaf.postgresService.Protocol,
				Username:    "postgres",
				Database:    "test",
			},
		})

		require.NoError(t, err)
		mustRunPostgresQuery(t, client)
		mustClosePostgresClient(t, client)
	})
}

func TestProxyAppAccess(t *testing.T) {
	pack := setupWithOptions(t, appTestOptions{
		rootClusterPorts: oneProxyPortSetup(),
		leafClusterPorts: oneProxyPortSetup(),
	})

	sess := pack.createAppSession(t, pack.rootAppPublicAddr, pack.rootAppClusterName)
	status, _, err := pack.makeRequest(sess, http.MethodGet, "/")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status)

	sess = pack.createAppSession(t, pack.leafAppPublicAddr, pack.leafAppClusterName)
	status, _, err = pack.makeRequest(sess, http.MethodGet, "/")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status)
}
