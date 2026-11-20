package crypto

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateSaveAndLoadWallet(t *testing.T) {
	tmpDir := t.TempDir()
	walletPath := filepath.Join(tmpDir, "wallets", "server_a.json")

	w, err := GenerateWallet("SERVER_A", RoleValidator)
	if err != nil {
		t.Fatalf("GenerateWallet falhou: %v", err)
	}
	if len(w.PublicKey) != 64 {
		t.Fatalf("esperava PublicKey de 64 chars hex, obteve %d", len(w.PublicKey))
	}
	if len(w.PrivateKey) != 128 {
		t.Fatalf("esperava PrivateKey de 128 chars hex, obteve %d", len(w.PrivateKey))
	}

	if err := SaveWallet(walletPath, w); err != nil {
		t.Fatalf("SaveWallet falhou: %v", err)
	}

	loaded, err := LoadWallet(walletPath)
	if err != nil {
		t.Fatalf("LoadWallet falhou: %v", err)
	}
	if loaded.ID != w.ID || loaded.Role != w.Role || loaded.PublicKey != w.PublicKey || loaded.PrivateKey != w.PrivateKey {
		t.Fatalf("carteira carregada difere da original: got=%+v want=%+v", loaded, w)
	}

	// LoadOrCreateWallet deve retornar a mesma carteira existente sem sobrescrever
	reloaded, err := LoadOrCreateWallet(walletPath, "OUTRO_ID", RolePassenger)
	if err != nil {
		t.Fatalf("LoadOrCreateWallet falhou: %v", err)
	}
	if reloaded.PublicKey != w.PublicKey {
		t.Fatalf("LoadOrCreateWallet não reaproveitou a carteira existente")
	}
}

func TestLoadWalletRejectsMismatchedKeyPair(t *testing.T) {
	tmpDir := t.TempDir()
	walletPath := filepath.Join(tmpDir, "mismatch.json")

	w1, _ := GenerateWallet("user1", RolePassenger)
	w2, _ := GenerateWallet("user2", RolePassenger)

	corrupted := `{"id":"user1","role":"PASSENGER","public_key":"` + w1.PublicKey + `","private_key":"` + w2.PrivateKey + `"}`
	if err := os.WriteFile(walletPath, []byte(corrupted), 0o600); err != nil {
		t.Fatalf("erro gravando arquivo: %v", err)
	}

	_, err := LoadWallet(walletPath)
	if !errors.Is(err, ErrKeyPairMismatch) {
		t.Fatalf("esperava ErrKeyPairMismatch, obteve: %v", err)
	}
}

func TestCanonicalSerializeDeterministic(t *testing.T) {
	a := map[string]any{
		"z_field": 42,
		"a_field": "valor",
		"nested": map[string]any{
			"b": true,
			"a": []any{3, 2, 1},
		},
	}
	b := map[string]any{
		"nested": map[string]any{
			"a": []any{3, 2, 1},
			"b": true,
		},
		"a_field": "valor",
		"z_field": 42,
	}

	ca, err := CanonicalSerialize(a)
	if err != nil {
		t.Fatalf("CanonicalSerialize(a) falhou: %v", err)
	}
	cb, err := CanonicalSerialize(b)
	if err != nil {
		t.Fatalf("CanonicalSerialize(b) falhou: %v", err)
	}

	if !bytes.Equal(ca, cb) {
		t.Fatalf("serialização canônica divergiu:\nA=%s\nB=%s", ca, cb)
	}
	if HashSHA256(ca) != HashSHA256(cb) {
		t.Fatalf("SHA-256 divergiu entre representações equivalentes")
	}
}

func TestSignAndVerifyValidPayload(t *testing.T) {
	w, err := GenerateWallet("Maria", RolePassenger)
	if err != nil {
		t.Fatalf("GenerateWallet falhou: %v", err)
	}

	payload, err := CanonicalSerialize(map[string]any{
		"action": "BOOK_ITINERARY",
		"nonce":  1,
		"amount": 5000,
	})
	if err != nil {
		t.Fatalf("CanonicalSerialize falhou: %v", err)
	}

	sig, err := SignPayload(w.PrivateKey, payload)
	if err != nil {
		t.Fatalf("SignPayload falhou: %v", err)
	}

	if err := VerifySignature(w.PublicKey, payload, sig); err != nil {
		t.Fatalf("VerifySignature rejeitou assinatura válida: %v", err)
	}
}

func TestVerifyRejectsTamperedSingleByte(t *testing.T) {
	w, _ := GenerateWallet("Maria", RolePassenger)
	payload := []byte(`{"action":"BOOK_ITINERARY","amount_cents":5000,"nonce":1}`)

	sig, err := w.Sign(payload)
	if err != nil {
		t.Fatalf("Sign falhou: %v", err)
	}

	// Adultera exatamente 1 byte do payload ('5' -> '6')
	tampered := append([]byte(nil), payload...)
	idx := bytes.IndexByte(tampered, '5')
	tampered[idx] = '6'

	err = VerifySignature(w.PublicKey, tampered, sig)
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("esperava ErrInvalidSignature para payload com 1 byte adulterado, obteve: %v", err)
	}
}

func TestVerifyRejectsWrongPrivateKey(t *testing.T) {
	victim, _ := GenerateWallet("Vitima", RolePassenger)
	attacker, _ := GenerateWallet("Atacante", RolePassenger)

	payload := []byte(`{"action":"BOOK_ITINERARY","nonce":1,"sender":"Vitima"}`)

	// Atacante assina com a própria chave privada tentando se passar pela chave pública da vítima
	forgedSig, err := SignPayload(attacker.PrivateKey, payload)
	if err != nil {
		t.Fatalf("SignPayload falhou: %v", err)
	}

	err = VerifySignature(victim.PublicKey, payload, forgedSig)
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("esperava ErrInvalidSignature para assinatura feita com chave privada de outro usuário, obteve: %v", err)
	}
}

func TestVerifyRejectsMalformedKeysAndSignatures(t *testing.T) {
	w, _ := GenerateWallet("Joao", RoleDriver)
	payload := []byte(`{"action":"BURN_CREDITS","nonce":1}`)
	validSig, _ := w.Sign(payload)

	if _, err := SignPayload("chave_invalida", payload); !errors.Is(err, ErrInvalidPrivateKey) {
		t.Fatalf("esperava ErrInvalidPrivateKey, obteve: %v", err)
	}
	if err := VerifySignature("pub_curta", payload, validSig); !errors.Is(err, ErrInvalidPublicKey) {
		t.Fatalf("esperava ErrInvalidPublicKey, obteve: %v", err)
	}
	if err := VerifySignature(w.PublicKey, payload, "sig_curta"); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("esperava ErrInvalidSignature para assinatura curta, obteve: %v", err)
	}
	if err := VerifySignature(w.PublicKey, payload, "zzzz"+validSig[4:]); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("esperava ErrInvalidSignature para assinatura hex inválida, obteve: %v", err)
	}
}
