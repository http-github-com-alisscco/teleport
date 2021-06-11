/*
Copyright 2020 Gravitational, Inc.

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

package ui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/tlsca"

	"github.com/aws/aws-sdk-go/aws/arn"
)

// App describes an application
type App struct {
	// Name is the name of the application.
	Name string `json:"name"`
	// URI is the internal address the application is available at.
	URI string `json:"uri"`
	// PublicAddr is the public address the application is accessible at.
	PublicAddr string `json:"publicAddr"`
	// FQDN is a fully qualified domain name of the application (app.example.com)
	FQDN string `json:"fqdn"`
	// ClusterID is this app cluster ID
	ClusterID string `json:"clusterId"`
	// Labels is a map of static labels associated with an application.
	Labels []Label `json:"labels"`
	// IsAWSConsole if true, indicates that the app represents AWS management console.
	IsAWSConsole bool `json:"isAWSConsole"`
	// AWSRoles is a list of AWS IAM roles for the application representing AWS console.
	AWSRoles []AWSRole `json:"awsRoles,omitempty"`
}

// AWSRole describes an AWS IAM role for AWS console access.
type AWSRole struct {
	// Display is the role display name.
	Display string `json:"display"`
	// ARN is the full role ARN.
	ARN string `json:"arn"`
}

// MakeAppsConfig contains parameters for converting apps to UI representation.
type MakeAppsConfig struct {
	// LocalClusterName is the name of the local cluster.
	LocalClusterName string
	// LocalProxyDNSName is the public hostname of the local cluster.
	LocalProxyDNSName string
	// AppClusterName is the name of the cluster apps reside in.
	AppClusterName string
	// Apps is a list of registered apps.
	Apps []types.Server
	// Identity is identity of the logged in user.
	Identity *tlsca.Identity
}

// MakeApps creates server application objects
func MakeApps(c MakeAppsConfig) []App {
	result := []App{}
	for _, server := range c.Apps {
		teleApps := server.GetApps()
		for _, teleApp := range teleApps {
			fqdn := AssembleAppFQDN(c.LocalClusterName, c.LocalProxyDNSName, c.AppClusterName, teleApp)
			labels := []Label{}
			for name, value := range teleApp.StaticLabels {
				labels = append(labels, Label{
					Name:  name,
					Value: value,
				})
			}

			sort.Sort(sortedLabels(labels))

			app := App{
				Name:         teleApp.Name,
				URI:          teleApp.URI,
				PublicAddr:   teleApp.PublicAddr,
				Labels:       labels,
				ClusterID:    c.AppClusterName,
				FQDN:         fqdn,
				IsAWSConsole: teleApp.IsAWSConsole(),
			}

			if teleApp.IsAWSConsole() {
				app.AWSRoles = filterAWSRoleARNs(c.Identity.AWSRoleARNs,
					teleApp.GetAWSAccountID())
			}

			result = append(result, app)
		}
	}

	return result
}

// filterAWSRoleARNs returns role ARNs from the provided list that belong
// to the specified AWS account ID.
func filterAWSRoleARNs(awsRoleARNS []string, awsAccountID string) (result []AWSRole) {
	for _, roleARN := range awsRoleARNS {
		parsed, err := arn.Parse(roleARN)
		if err != nil || parsed.AccountID != awsAccountID {
			continue
		}
		// Example ARN: arn:aws:iam::1234567890:role/EC2FullAccess.
		parts := strings.Split(parsed.Resource, "/")
		if len(parts) != 2 || parts[0] != "role" {
			continue
		}
		result = append(result, AWSRole{
			Display: parts[1],
			ARN:     roleARN,
		})
	}
	return result
}

// AssembleAppFQDN returns the application's FQDN.
//
// If the application is running within the local cluster and it has a public
// address specified, the application's public address is used.
//
// In all other cases, i.e. if the public address is not set or the application
// is running in a remote cluster, the FQDN is formatted as
// <appName>.<localProxyDNSName>
func AssembleAppFQDN(localClusterName string, localProxyDNSName string, appClusterName string, app *types.App) string {
	isLocalCluster := localClusterName == appClusterName
	if isLocalCluster && app.PublicAddr != "" {
		return app.PublicAddr
	}
	return fmt.Sprintf("%v.%v", app.Name, localProxyDNSName)
}
