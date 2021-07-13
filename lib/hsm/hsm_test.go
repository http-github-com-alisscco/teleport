package hsm_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509/pkix"
	"os"
	"testing"

	apidefaults "github.com/gravitational/teleport/api/defaults"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth/native"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/hsm"
	"github.com/gravitational/teleport/lib/tlsca"
	"github.com/jonboulle/clockwork"
	"golang.org/x/crypto/ssh"

	"github.com/stretchr/testify/require"
)

func TestHSM(t *testing.T) {
	yubiSlotNumber := 0
	testcases := []struct {
		desc         string
		clientConfig hsm.ClientConfig
		shouldSkip   func() bool
	}{
		{
			desc: "null client",
			clientConfig: hsm.ClientConfig{
				RSAKeyPairSource: native.GenerateKeyPair,
			},
			shouldSkip: func() bool { return false },
		},
		{
			desc: "softhsm",
			clientConfig: hsm.ClientConfig{
				Path:       "/usr/local/lib/softhsm/libsofthsm2.so",
				TokenLabel: "test",
				Pin:        "password",
				HostUUID:   "server1",
			},
			shouldSkip: func() bool { return os.Getenv("SOFTHSM2_CONF") == "" },
		},
		{
			desc: "yubihsm",
			clientConfig: hsm.ClientConfig{
				Path:       "/usr/local/Cellar/p11-kit/0.23.22/lib/pkcs11/yubihsm_pkcs11.dylib",
				SlotNumber: &yubiSlotNumber,
				Pin:        "0001password",
				HostUUID:   "server1",
			},
			shouldSkip: func() bool { return os.Getenv("YUBIHSM_PKCS11_CONF") == "" },
		},
	}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.desc, func(t *testing.T) {
			if tc.shouldSkip() {
				return
			}
			t.Parallel()
			client, err := hsm.NewClient(&tc.clientConfig)
			require.NoError(t, err)

			key, err := client.GenerateRSA()
			require.NoError(t, err)

			signer, err := client.GetSigner(key)
			require.NoError(t, err)
			require.NotNil(t, signer)

			message := []byte("Lorem ipsum dolor sit amet...")
			hashed := sha256.Sum256(message)

			signature, err := signer.Sign(rand.Reader, hashed[:], crypto.SHA256)
			require.NoError(t, err)
			require.NotEmpty(t, signature)

			err = rsa.VerifyPKCS1v15(signer.Public().(*rsa.PublicKey), crypto.SHA256, hashed[:], signature)
			require.NoError(t, err)

			sshSigner, err := ssh.NewSignerFromSigner(signer)
			require.NoError(t, err)
			sshPublicKey := ssh.MarshalAuthorizedKey(sshSigner.PublicKey())

			tlsCert, err := tlsca.GenerateSelfSignedCAWithSigner(
				signer,
				pkix.Name{
					CommonName:   "server1",
					Organization: []string{"server1"},
				}, nil, defaults.CATTL)

			ca := &types.CertAuthorityV2{
				Kind:    types.KindCertAuthority,
				Version: types.V2,
				Metadata: types.Metadata{
					Name:      "server1",
					Namespace: apidefaults.Namespace,
				},
				Spec: types.CertAuthoritySpecV2{
					ClusterName: "server1",
					ActiveKeys: types.CAKeySet{
						SSH: []*types.SSHKeyPair{
							&types.SSHKeyPair{
								PrivateKey:     key,
								PrivateKeyType: hsm.KeyType(key),
								PublicKey:      sshPublicKey,
							},
						},
						TLS: []*types.TLSKeyPair{
							&types.TLSKeyPair{
								Key:     key,
								KeyType: hsm.KeyType(key),
								Cert:    tlsCert,
							},
						},
						JWT: []*types.JWTKeyPair{
							&types.JWTKeyPair{
								PrivateKey:     key,
								PrivateKeyType: hsm.KeyType(key),
								PublicKey:      sshPublicKey,
							},
						},
					},
				},
			}

			_, err = client.GetSSHSigner(ca)
			require.NoError(t, err)
			_, _, err = client.GetTLSCertAndSigner(ca)
			require.NoError(t, err)
			_, err = client.GetJWTSigner(ca, clockwork.NewFakeClock())
			require.NoError(t, err)
		})
	}
}
