package api

type Op string

const (
	OpHealth        Op = "HEALTH"
	OpSign          Op = "SIGN"
	OpGenKeyAndSign Op = "GENKEY_AND_SIGN"
	OpRevoke        Op = "REVOKE"
	OpGetCRL        Op = "GET_CRL"
	OpListIssued    Op = "LIST_ISSUED"
)

type Profile string

const (
	ProfileClient Profile = "client"
	ProfileServer Profile = "server"
)

type KeyType string

const (
	KeyRSA4096 KeyType = "rsa4096"
	KeyEd25519 KeyType = "ed25519"
)

type Request struct {
	Op         Op      `json:"op"`
	CN         string  `json:"cn,omitempty"`
	Profile    Profile `json:"profile,omitempty"`
	CSRPEM     string  `json:"csr_pem,omitempty"`
	KeyType    KeyType `json:"key_type,omitempty"`
	Passphrase string  `json:"passphrase,omitempty"`
	Serial     string  `json:"serial,omitempty"`
	Reason     string  `json:"reason,omitempty"`
}

type Response struct {
	CertPEM   string       `json:"cert_pem,omitempty"`
	KeyPEMEnc string       `json:"key_pem_encrypted,omitempty"`
	CRLPEM    string       `json:"crl_pem,omitempty"`
	Serial    string       `json:"serial,omitempty"`
	NotAfter  string       `json:"not_after,omitempty"`
	Issued    []IssuedMeta `json:"issued,omitempty"`
	Error     string       `json:"err,omitempty"`
}

type IssuedMeta struct {
	Serial   string `json:"serial"`
	CN       string `json:"cn"`
	Profile  string `json:"profile"`
	NotAfter string `json:"not_after"`
	SHA256   string `json:"sha256"`
}
