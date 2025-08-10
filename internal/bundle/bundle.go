package bundle

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"regexp"
	"time"
)

var reCN = regexp.MustCompile(`^[A-Za-z0-9._-]{3,64}$`)

type Inputs struct {
	CN         string
	CAPEM      string
	TaKey      string
	CertPEM    string
	KeyPEMOpt  string
	RemoteHost string
	RemotePort int
	Proto      string
}

type Outputs struct {
	ZipBytes []byte
}

func sanitizeCN(cn string) error {
	if !reCN.MatchString(cn) {
		return fmt.Errorf("invalid CN")
	}
	return nil
}

func Build(inputs Inputs) (Outputs, error) {
	if err := sanitizeCN(inputs.CN); err != nil {
		return Outputs{}, err
	}
	if inputs.RemoteHost == "" || inputs.RemotePort <= 0 {
		return Outputs{}, fmt.Errorf("remote not set")
	}
	if inputs.Proto == "" {
		inputs.Proto = "udp"
	}

	refOvpn := renderRefOvpn(inputs)
	inlineOvpn := renderInlineOvpn(inputs)

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	add := func(name string, data []byte) error {
		w, err := zw.Create(name)
		if err != nil {
			return err
		}
		_, err = w.Write(data)
		return err
	}

	base := inputs.CN
	if err := add(filepath.Join(base, "ca.crt"), []byte(inputs.CAPEM)); err != nil {
		return Outputs{}, err
	}
	if err := add(filepath.Join(base, "ta.key"), []byte(inputs.TaKey)); err != nil {
		return Outputs{}, err
	}
	if err := add(filepath.Join(base, inputs.CN+".crt"), []byte(inputs.CertPEM)); err != nil {
		return Outputs{}, err
	}
	if inputs.KeyPEMOpt != "" {
		if err := add(filepath.Join(base, inputs.CN+".key"), []byte(inputs.KeyPEMOpt)); err != nil {
			return Outputs{}, err
		}
	}
	if err := add(filepath.Join(base, "client.ovpn"), []byte(refOvpn)); err != nil {
		return Outputs{}, err
	}
	if err := add(filepath.Join(base, "client-inline.ovpn"), []byte(inlineOvpn)); err != nil {
		return Outputs{}, err
	}

	meta := fmt.Sprintf(
		"cn=%s\ngenerated_at_utc=%s\nproto=%s\nremote=%s:%d\ncapem_sha256_b64=%s\n",
		inputs.CN,
		time.Now().UTC().Format(time.RFC3339),
		inputs.Proto,
		inputs.RemoteHost,
		inputs.RemotePort,
		base64.StdEncoding.EncodeToString(sumSHA256([]byte(inputs.CAPEM))),
	)
	_ = add(filepath.Join(base, ".bundle.meta"), []byte(meta))

	if err := zw.Close(); err != nil {
		return Outputs{}, err
	}
	return Outputs{ZipBytes: buf.Bytes()}, nil
}

func renderRefOvpn(in Inputs) string {
	return fmt.Sprintf(`client
dev tun
proto %s
remote %s %d
resolv-retry infinite
nobind
persist-key
persist-tun
cipher AES-256-GCM
auth SHA512
remote-cert-tls server
verb 3
key-direction 1

ca ca.crt
cert %s.crt
tls-crypt ta.key
%s
`, in.Proto, in.RemoteHost, in.RemotePort, in.CN, keyRefLine(in))
}

func keyRefLine(in Inputs) string {
	if in.KeyPEMOpt == "" {
		return fmt.Sprintf("# key %s.key", in.CN)
	}
	return fmt.Sprintf("key %s.key", in.CN)
}

func renderInlineOvpn(in Inputs) string {
	var keySection string
	if in.KeyPEMOpt != "" {
		keySection = fmt.Sprintf("<key>\n%s\n</key>\n", trim(in.KeyPEMOpt))
	} else {
		keySection = "# <key>\n# provide your private key or use file-referencing profile\n# </key>\n"
	}
	return fmt.Sprintf(`client
dev tun
proto %s
remote %s %d
resolv-retry infinite
nobind
persist-key
persist-tun
cipher AES-256-GCM
auth SHA512
remote-cert-tls server
verb 3
key-direction 1

<ca>
%s
</ca>
<cert>
%s
</cert>
<tls-crypt>
%s
</tls-crypt>
%s`, in.Proto, in.RemoteHost, in.RemotePort, trim(in.CAPEM), trim(in.CertPEM), trim(in.TaKey), keySection)
}

func trim(s string) string {
	return string(bytes.TrimSpace([]byte(s)))
}

func sumSHA256(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}
