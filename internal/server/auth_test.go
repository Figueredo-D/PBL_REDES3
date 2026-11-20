package server

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/Figueredo-D/PBL_REDES/internal/crypto"
	"github.com/Figueredo-D/PBL_REDES/internal/protocol"
)

func buildSignedRequest(t *testing.T, w *crypto.Wallet, action string, nonce uint64, payload any) protocol.Request {
	t.Helper()
	var dataStr string
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("falha ao serializar payload: %v", err)
		}
		dataStr = string(b)
	}

	req := protocol.Request{
		Action:       action,
		Token:        w.PublicKey,
		Data:         dataStr,
		SenderPubKey: w.PublicKey,
		Nonce:        nonce,
		Timestamp:    time.Now().Unix(),
	}
	if err := protocol.SignRequest(&req, w.PrivateKey); err != nil {
		t.Fatalf("SignRequest falhou: %v", err)
	}
	return req
}

func TestRequestValidatorAcceptsValidAndBlocksReplay(t *testing.T) {
	v := NewRequestValidator()
	user, _ := crypto.GenerateWallet("Maria", crypto.RolePassenger)

	req1 := buildSignedRequest(t, user, protocol.ActionBookItinerary, 1, map[string]string{"itinerary_id": "IT_1"})
	if err := v.ValidateAndAccept(req1); err != nil {
		t.Fatalf("requisição válida com nonce 1 foi rejeitada: %v", err)
	}

	// Replay exato (mesmo nonce = 1) deve ser rejeitado imediatamente
	if err := v.ValidateAndAccept(req1); err == nil || err.Code != "REPLAY_ATTACK" {
		t.Fatalf("esperava REPLAY_ATTACK para nonce repetido, obteve: %v", err)
	}

	// Nonce subsequente (nonce = 2) deve ser aceito
	req2 := buildSignedRequest(t, user, protocol.ActionBookItinerary, 2, map[string]string{"itinerary_id": "IT_2"})
	if err := v.ValidateAndAccept(req2); err != nil {
		t.Fatalf("requisição válida com nonce 2 foi rejeitada: %v", err)
	}
}

func TestRequestValidatorRejectsUnsignedAndTampered(t *testing.T) {
	tmpDir := t.TempDir()
	srv, err := NewServer(":0", "SERVER_A", nil, filepath.Join(tmpDir, "estado.json"))
	if err != nil {
		t.Fatalf("NewServer falhou: %v", err)
	}

	// 1. Operação de escrita sem assinatura deve ser rejeitada antes do handler
	unsignedResp := srv.route(protocol.Request{
		Action: protocol.ActionSubmitReputation,
		Token:  "usuario_sem_assinatura",
		Data:   `{"booking_id":"B1","score":5}`,
	})
	if unsignedResp.Status != "ERROR" || unsignedResp.Code != "MISSING_SIGNATURE" {
		t.Fatalf("esperava MISSING_SIGNATURE, obteve: %+v", unsignedResp)
	}

	// 2. Mensagem com 1 byte adulterado após assinatura deve ser rejeitada
	user, _ := crypto.GenerateWallet("Carlos", crypto.RolePassenger)
	req := buildSignedRequest(t, user, protocol.ActionSubmitReputation, 1, protocol.SubmitReputationData{
		BookingID:    "BOOK_1",
		TargetPubKey: "abc",
		Category:     "RATING",
		Score:        5,
		Comment:      "Excelente",
	})
	req.Data = req.Data[:len(req.Data)-2] + `!"` // altera conteúdo assinado

	tamperedResp := srv.route(req)
	if tamperedResp.Status != "ERROR" || tamperedResp.Code != "INVALID_SIGNATURE" {
		t.Fatalf("esperava INVALID_SIGNATURE para payload adulterado, obteve: %+v", tamperedResp)
	}
}

func TestRequestValidatorRejectsImpersonation(t *testing.T) {
	v := NewRequestValidator()
	victim, _ := crypto.GenerateWallet("Vitima", crypto.RolePassenger)
	attacker, _ := crypto.GenerateWallet("Atacante", crypto.RolePassenger)

	// Caso A: Atacante coloca SenderPubKey da vítima mas assina com a própria chave privada
	reqA := protocol.Request{
		Action:       protocol.ActionBookItinerary,
		Token:        victim.PublicKey,
		Data:         `{"itinerary_id":"IT_1"}`,
		SenderPubKey: victim.PublicKey,
		Nonce:        1,
		Timestamp:    time.Now().Unix(),
	}
	if err := protocol.SignRequest(&reqA, attacker.PrivateKey); err != nil {
		t.Fatalf("SignRequest falhou: %v", err)
	}
	if err := v.ValidateAndAccept(reqA); err == nil || err.Code != "INVALID_SIGNATURE" {
		t.Fatalf("esperava INVALID_SIGNATURE na tentativa de falsificação de chave, obteve: %v", err)
	}

	// Caso B: Atacante assina com sua própria chave, mas tenta operar com Token da vítima
	reqB := protocol.Request{
		Action:       protocol.ActionCancelBooking,
		Token:        victim.PublicKey,
		Data:         `{"booking_id":"BOOK_1"}`,
		SenderPubKey: attacker.PublicKey,
		Nonce:        1,
		Timestamp:    time.Now().Unix(),
	}
	if err := protocol.SignRequest(&reqB, attacker.PrivateKey); err != nil {
		t.Fatalf("SignRequest falhou: %v", err)
	}
	if err := v.ValidateAndAccept(reqB); err == nil || err.Code != "IMPERSONATION_DETECTED" {
		t.Fatalf("esperava IMPERSONATION_DETECTED, obteve: %v", err)
	}
}

func TestRequestValidatorMintRequiresAuthorizedValidator(t *testing.T) {
	v := NewRequestValidator()
	companyA, _ := crypto.GenerateWallet("SERVER_A", crypto.RoleValidator)
	passenger, _ := crypto.GenerateWallet("Maria", crypto.RolePassenger)

	if err := v.RegisterValidator("SERVER_A", companyA.PublicKey); err != nil {
		t.Fatalf("RegisterValidator falhou: %v", err)
	}

	mintPayload := protocol.MintCreditsData{
		TargetPubKey: passenger.PublicKey,
		AmountCents:  10000,
		CompanyID:    "SERVER_A",
		ReferenceID:  "DEP_001",
	}

	// Passageiro comum tentando fazer MINT deve ser barrado
	reqUser := buildSignedRequest(t, passenger, protocol.ActionMintCredits, 1, mintPayload)
	if err := v.ValidateAndAccept(reqUser); err == nil || err.Code != "UNAUTHORIZED_VALIDATOR" {
		t.Fatalf("esperava UNAUTHORIZED_VALIDATOR para usuário comum tentando MINT, obteve: %v", err)
	}

	// Empresa validadora autorizada assinando MINT deve ser aceita
	reqCompany := buildSignedRequest(t, companyA, protocol.ActionMintCredits, 1, mintPayload)
	if err := v.ValidateAndAccept(reqCompany); err != nil {
		t.Fatalf("MINT assinado por empresa autorizada foi rejeitado: %v", err)
	}
}

func TestRequestValidatorAllowsUnsignedReadRequests(t *testing.T) {
	tmpDir := t.TempDir()
	srv, err := NewServer(":0", "SERVER_A", nil, filepath.Join(tmpDir, "estado.json"))
	if err != nil {
		t.Fatalf("NewServer falhou: %v", err)
	}

	resp := srv.route(protocol.Request{
		Action: protocol.ActionListRides,
		Token:  "qualquer_chave_ou_id",
	})
	if resp.Status != "SUCCESS" {
		t.Fatalf("esperava SUCCESS em consulta de leitura sem assinatura, obteve: %+v", resp)
	}
}
