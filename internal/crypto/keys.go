package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

const (
	RoleValidator = "VALIDATOR"
	RolePassenger = "PASSENGER"
	RoleDriver    = "DRIVER"
)

var (
	ErrInvalidPublicKey  = errors.New("chave pública Ed25519 inválida")
	ErrInvalidPrivateKey = errors.New("chave privada Ed25519 inválida")
	ErrInvalidSignature  = errors.New("assinatura Ed25519 inválida ou não corresponde ao payload")
	ErrKeyPairMismatch   = errors.New("chave pública não corresponde à chave privada armazenada")
)

// Wallet representa a identidade criptográfica Ed25519 de um usuário ou nó validador.
type Wallet struct {
	ID         string `json:"id"`          // Rótulo legível (ex: "SERVER_A", "Maria")
	Role       string `json:"role"`        // "VALIDATOR", "PASSENGER" ou "DRIVER"
	PublicKey  string `json:"public_key"`  // Chave pública Ed25519 codificada em hex (64 caracteres)
	PrivateKey string `json:"private_key"` // Chave privada Ed25519 codificada em hex (128 caracteres)
}

// GenerateWallet gera um novo par de chaves Ed25519 criptograficamente seguro.
func GenerateWallet(id, role string) (*Wallet, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("falha ao gerar par de chaves Ed25519: %w", err)
	}

	return &Wallet{
		ID:         id,
		Role:       role,
		PublicKey:  hex.EncodeToString(pub),
		PrivateKey: hex.EncodeToString(priv),
	}, nil
}

// Address retorna a identidade pública global da carteira (chave pública em hex).
func (w *Wallet) Address() string {
	if w == nil {
		return ""
	}
	return w.PublicKey
}

// Sign assina o payload informado usando a chave privada da carteira.
func (w *Wallet) Sign(payload []byte) (string, error) {
	if w == nil {
		return "", ErrInvalidPrivateKey
	}
	return SignPayload(w.PrivateKey, payload)
}

// SaveWallet persiste a carteira em disco de forma atômica (.tmp + rename) com permissão 0600.
func SaveWallet(path string, w *Wallet) error {
	if w == nil {
		return errors.New("carteira nula")
	}
	if err := validateWalletKeys(w); err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("falha ao criar diretório da carteira: %w", err)
	}

	data, err := json.MarshalIndent(w, "", "  ")
	if err != nil {
		return fmt.Errorf("falha ao serializar carteira: %w", err)
	}

	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o600); err != nil {
		return fmt.Errorf("falha ao gravar arquivo temporário da carteira: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("falha ao persistir carteira em %s: %w", path, err)
	}
	return nil
}

// LoadWallet carrega uma carteira do disco e valida a integridade do par de chaves Ed25519.
func LoadWallet(path string) (*Wallet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var w Wallet
	if err := json.Unmarshal(data, &w); err != nil {
		return nil, fmt.Errorf("arquivo de carteira corrompido: %w", err)
	}
	if err := validateWalletKeys(&w); err != nil {
		return nil, err
	}
	return &w, nil
}

// LoadOrCreateWallet carrega a carteira em path se existir; caso contrário gera e salva uma nova.
func LoadOrCreateWallet(path, id, role string) (*Wallet, error) {
	w, err := LoadWallet(path)
	if err == nil {
		return w, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}

	w, err = GenerateWallet(id, role)
	if err != nil {
		return nil, err
	}
	if err := SaveWallet(path, w); err != nil {
		return nil, err
	}
	return w, nil
}

// ValidatePublicKeyHex verifica se a string hex representa uma chave pública Ed25519 válida.
func ValidatePublicKeyHex(pubKeyHex string) error {
	_, err := decodePublicKey(pubKeyHex)
	return err
}

func decodePublicKey(pubKeyHex string) (ed25519.PublicKey, error) {
	if len(pubKeyHex) != ed25519.PublicKeySize*2 {
		return nil, fmt.Errorf("%w: tamanho esperado %d caracteres hex, recebido %d",
			ErrInvalidPublicKey, ed25519.PublicKeySize*2, len(pubKeyHex))
	}
	raw, err := hex.DecodeString(pubKeyHex)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, ErrInvalidPublicKey
	}
	return ed25519.PublicKey(raw), nil
}

func decodePrivateKey(privKeyHex string) (ed25519.PrivateKey, error) {
	if len(privKeyHex) != ed25519.PrivateKeySize*2 {
		return nil, fmt.Errorf("%w: tamanho esperado %d caracteres hex, recebido %d",
			ErrInvalidPrivateKey, ed25519.PrivateKeySize*2, len(privKeyHex))
	}
	raw, err := hex.DecodeString(privKeyHex)
	if err != nil || len(raw) != ed25519.PrivateKeySize {
		return nil, ErrInvalidPrivateKey
	}
	return ed25519.PrivateKey(raw), nil
}

func validateWalletKeys(w *Wallet) error {
	pub, err := decodePublicKey(w.PublicKey)
	if err != nil {
		return err
	}
	priv, err := decodePrivateKey(w.PrivateKey)
	if err != nil {
		return err
	}
	derivedPub, ok := priv.Public().(ed25519.PublicKey)
	if !ok || !bytes.Equal(pub, derivedPub) {
		return ErrKeyPairMismatch
	}
	return nil
}

// SignPayload gera uma assinatura digital Ed25519 (em hex) para o payload canônico informado.
func SignPayload(privKeyHex string, payload []byte) (string, error) {
	priv, err := decodePrivateKey(privKeyHex)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(priv, payload)
	return hex.EncodeToString(sig), nil
}

// VerifySignature valida se signatureHex é uma assinatura Ed25519 autêntica do payload para pubKeyHex.
func VerifySignature(pubKeyHex string, payload []byte, signatureHex string) error {
	pub, err := decodePublicKey(pubKeyHex)
	if err != nil {
		return err
	}
	if len(signatureHex) != ed25519.SignatureSize*2 {
		return fmt.Errorf("%w: tamanho esperado %d caracteres hex, recebido %d",
			ErrInvalidSignature, ed25519.SignatureSize*2, len(signatureHex))
	}
	sig, err := hex.DecodeString(signatureHex)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return ErrInvalidSignature
	}
	if !ed25519.Verify(pub, payload, sig) {
		return ErrInvalidSignature
	}
	return nil
}

// HashSHA256 calcula o digest SHA-256 em hexadecimal minúsculo dos bytes informados.
func HashSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// CanonicalSerialize converte qualquer estrutura ou JSON em uma representação JSON compacta
// e determinística, com chaves de objetos ordenadas lexicograficamente em todos os níveis.
// Isso garante que todos os nós produzam exatamente os mesmos bytes ao recalcular hashes e assinaturas.
func CanonicalSerialize(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("falha ao serializar objeto para forma canônica: %w", err)
	}
	return CanonicalizeJSON(raw)
}

// CanonicalizeJSON normaliza um documento JSON arbitrário ordenando recursivamente as chaves
// de todos os objetos e removendo espaços supérfluos, preservando números com precisão exata.
func CanonicalizeJSON(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()

	var parsed any
	if err := dec.Decode(&parsed); err != nil {
		return nil, fmt.Errorf("JSON inválido para canonicalização: %w", err)
	}

	var buf bytes.Buffer
	if err := writeCanonical(&buf, parsed); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonical(buf *bytes.Buffer, v any) error {
	switch val := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if val {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case json.Number:
		buf.WriteString(val.String())
	case string:
		b, err := json.Marshal(val)
		if err != nil {
			return err
		}
		buf.Write(b)
	case []any:
		buf.WriteByte('[')
		for i, elem := range val {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, elem); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			kb, err := json.Marshal(k)
			if err != nil {
				return err
			}
			buf.Write(kb)
			buf.WriteByte(':')
			if err := writeCanonical(buf, val[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		b, err := json.Marshal(val)
		if err != nil {
			return err
		}
		buf.Write(b)
	}
	return nil
}
