package server

import (
	"fmt"
	"sync"

	"github.com/Figueredo-D/PBL_REDES/internal/crypto"
	"github.com/Figueredo-D/PBL_REDES/internal/protocol"
)

// AuthError representa uma falha na camada de validação criptográfica/autorização de entrada.
type AuthError struct {
	Code    string
	Message string
}

func (e *AuthError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// RequestValidator atua como interceptor de segurança na entrada das requisições dos clientes/nós.
// Ele valida assinaturas Ed25519, bloqueia replay attacks por Nonce monotônico e restringe
// operações privilegiadas (como MINT_CREDITS) apenas às chaves autorizadas dos validadores.
type RequestValidator struct {
	mu                   sync.RWMutex
	lastNonces           map[string]uint64 // senderPubKey -> último nonce aceito
	authorizedValidators map[string]string // validatorPubKey -> validatorID (ex: SERVER_A)
}

// NewRequestValidator instancia um novo validador de requisições.
func NewRequestValidator() *RequestValidator {
	return &RequestValidator{
		lastNonces:           make(map[string]uint64),
		authorizedValidators: make(map[string]string),
	}
}

// RegisterValidator autoriza a chave pública de uma empresa validadora do consórcio.
func (v *RequestValidator) RegisterValidator(validatorID, pubKeyHex string) error {
	if err := crypto.ValidatePublicKeyHex(pubKeyHex); err != nil {
		return fmt.Errorf("chave pública inválida para validador %s: %w", validatorID, err)
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.authorizedValidators[pubKeyHex] = validatorID
	return nil
}

// IsAuthorizedValidator informa se a chave pública pertence a uma empresa validadora autorizada.
func (v *RequestValidator) IsAuthorizedValidator(pubKeyHex string) bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	_, ok := v.authorizedValidators[pubKeyHex]
	return ok
}

// LastNonce retorna o último nonce aceito para uma chave pública.
func (v *RequestValidator) LastNonce(pubKeyHex string) uint64 {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.lastNonces[pubKeyHex]
}

// SyncNonce sincroniza o nonce local (útil ao reconstruir o estado do ledger na inicialização/sync).
func (v *RequestValidator) SyncNonce(pubKeyHex string, nonce uint64) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if nonce > v.lastNonces[pubKeyHex] {
		v.lastNonces[pubKeyHex] = nonce
	}
}

// RequiresSignature define quais ações alteram estado financeiro, reservas ou reputação
// e portanto exigem obrigatoriamente assinatura Ed25519, Nonce e Timestamp.
// Ações puramente de consulta/leitura retornam false para preservar compatibilidade.
func RequiresSignature(action string) bool {
	switch action {
	case protocol.ActionOfferRide,
		protocol.ActionBookItinerary,
		protocol.ActionCancelBooking,
		protocol.ActionCancelRide,
		protocol.ActionMintCredits,
		protocol.ActionBurnCredits,
		protocol.ActionCompleteTrip,
		protocol.ActionReportNoShow,
		protocol.ActionSubmitReputation:
		return true
	default:
		return false
	}
}

// RequiresValidatorRole define ações privilegiadas restritas às empresas validadoras do consórcio.
func RequiresValidatorRole(action string) bool {
	switch action {
	case protocol.ActionMintCredits:
		return true
	default:
		return false
	}
}

// ValidateAndAccept executa todas as verificações criptográficas e anti-replay na entrada da requisição.
// Se a requisição for rejeitada, o nonce da conta NÃO é alterado.
func (v *RequestValidator) ValidateAndAccept(req protocol.Request) *AuthError {
	if !RequiresSignature(req.Action) {
		return nil
	}

	if req.SenderPubKey == "" || req.Signature == "" {
		return &AuthError{
			Code:    "MISSING_SIGNATURE",
			Message: fmt.Sprintf("a ação '%s' exige sender_pub_key e signature Ed25519 válidos", req.Action),
		}
	}

	if req.Nonce == 0 {
		return &AuthError{
			Code:    "INVALID_NONCE",
			Message: "nonce deve ser estritamente maior que zero",
		}
	}

	if req.Timestamp <= 0 {
		return &AuthError{
			Code:    "INVALID_TIMESTAMP",
			Message: "timestamp deve ser um Unix timestamp positivo gerado na origem",
		}
	}

	// Impede que um usuário assine com sua chave mas informe Token de outro usuário
	if req.Token != "" && req.Token != req.SenderPubKey {
		return &AuthError{
			Code:    "IMPERSONATION_DETECTED",
			Message: "token divergente de sender_pub_key: não é permitido operar em nome de terceiros",
		}
	}

	// 1. Verifica assinatura digital Ed25519 sobre todos os campos canônicos (inclui Nonce e Timestamp)
	if err := protocol.VerifyRequestSignature(req); err != nil {
		return &AuthError{
			Code:    "INVALID_SIGNATURE",
			Message: fmt.Sprintf("assinatura digital inválida: %v", err),
		}
	}

	// 2. Para ações privilegiadas (ex: MINT_CREDITS), exige chave pública de empresa validadora autorizada
	if RequiresValidatorRole(req.Action) && !v.IsAuthorizedValidator(req.SenderPubKey) {
		return &AuthError{
			Code:    "UNAUTHORIZED_VALIDATOR",
			Message: fmt.Sprintf("a ação privilegiada '%s' só pode ser assinada por um nó validador autorizado", req.Action),
		}
	}

	// 3. Proteção anti-replay: exige Nonce estritamente maior que o último confirmado para esta chave pública
	v.mu.Lock()
	defer v.mu.Unlock()

	last := v.lastNonces[req.SenderPubKey]
	if req.Nonce <= last {
		return &AuthError{
			Code:    "REPLAY_ATTACK",
			Message: fmt.Sprintf("nonce %d já utilizado ou fora de ordem (último aceito: %d)", req.Nonce, last),
		}
	}

	v.lastNonces[req.SenderPubKey] = req.Nonce
	return nil
}
