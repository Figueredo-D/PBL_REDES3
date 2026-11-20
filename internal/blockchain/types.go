package blockchain

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Figueredo-D/PBL_REDES/internal/crypto"
)

// TxType identifica o tipo de operação registrada de forma imutável na blockchain.
type TxType string

const (
	TxMint          TxType = "MINT"
	TxBurn          TxType = "BURN"
	TxReserveEscrow TxType = "RESERVE_ESCROW"
	TxCompleteTrip  TxType = "COMPLETE_TRIP"
	TxCancelTrip    TxType = "CANCEL_TRIP"
	TxNoShow        TxType = "NO_SHOW"
	TxReputation    TxType = "REPUTATION"
)

// Transaction representa uma operação assinada digitalmente que altera o estado do ledger.
type Transaction struct {
	ID            string          `json:"id"`             // SHA-256 hex do conteúdo canônico (sem ID e Signature)
	Type          TxType          `json:"type"`           // Tipo da transação
	FromPubKey    string          `json:"from_pub_key"`   // Chave pública Ed25519 (hex) do autor
	Nonce         uint64          `json:"nonce"`          // Contador sequencial da conta FromPubKey
	TimestampUnix int64           `json:"timestamp_unix"` // Carimbo de tempo Unix gerado na origem
	Payload       json.RawMessage `json:"payload"`        // JSON canônico específico do TxType
	Signature     string          `json:"signature"`      // Assinatura Ed25519 (hex) sobre o conteúdo canônico
}

type canonicalTxBody struct {
	FromPubKey    string          `json:"from_pub_key"`
	Nonce         uint64          `json:"nonce"`
	Payload       json.RawMessage `json:"payload"`
	TimestampUnix int64           `json:"timestamp_unix"`
	Type          TxType          `json:"type"`
}

// CanonicalBytes gera os bytes determinísticos de uma transação para hash e assinatura.
func (tx Transaction) CanonicalBytes() ([]byte, error) {
	canonPayload, err := crypto.CanonicalizeJSON(tx.Payload)
	if err != nil {
		return nil, fmt.Errorf("payload inválido na transação: %w", err)
	}
	body := canonicalTxBody{
		FromPubKey:    tx.FromPubKey,
		Nonce:         tx.Nonce,
		Payload:       json.RawMessage(canonPayload),
		TimestampUnix: tx.TimestampUnix,
		Type:          tx.Type,
	}
	return crypto.CanonicalSerialize(body)
}

// ComputeID calcula o hash SHA-256 determinístico da transação.
func (tx Transaction) ComputeID() (string, error) {
	raw, err := tx.CanonicalBytes()
	if err != nil {
		return "", err
	}
	return crypto.HashSHA256(raw), nil
}

// NewSignedTransaction cria, canonicaliza, calcula o ID e assina uma transação com a carteira informada.
func NewSignedTransaction(w *crypto.Wallet, txType TxType, nonce uint64, timestampUnix int64, payload any) (Transaction, error) {
	if w == nil {
		return Transaction{}, errors.New("carteira nula")
	}
	payloadBytes, err := crypto.CanonicalSerialize(payload)
	if err != nil {
		return Transaction{}, err
	}

	tx := Transaction{
		Type:          txType,
		FromPubKey:    w.PublicKey,
		Nonce:         nonce,
		TimestampUnix: timestampUnix,
		Payload:       json.RawMessage(payloadBytes),
	}

	canonBytes, err := tx.CanonicalBytes()
	if err != nil {
		return Transaction{}, err
	}
	tx.ID = crypto.HashSHA256(canonBytes)

	sig, err := w.Sign(canonBytes)
	if err != nil {
		return Transaction{}, err
	}
	tx.Signature = sig
	return tx, nil
}

// VerifySignature valida o ID (SHA-256) e a assinatura Ed25519 da transação.
func (tx Transaction) VerifySignature() error {
	if tx.TimestampUnix <= 0 {
		return errors.New("timestamp_unix da transação deve ser positivo")
	}
	if tx.Nonce == 0 {
		return errors.New("nonce da transação deve ser maior que zero")
	}
	canonBytes, err := tx.CanonicalBytes()
	if err != nil {
		return err
	}
	expectedID := crypto.HashSHA256(canonBytes)
	if tx.ID != expectedID {
		return fmt.Errorf("ID da transação inválido: esperado %s, recebido %s", expectedID, tx.ID)
	}
	return crypto.VerifySignature(tx.FromPubKey, canonBytes, tx.Signature)
}

// --- Payloads específicos por tipo de transação ---

type MintPayload struct {
	TargetPubKey string `json:"target_pub_key"`
	AmountCents  int64  `json:"amount_cents"`
	CompanyID    string `json:"company_id"`
	ReferenceID  string `json:"reference_id"`
}

type BurnPayload struct {
	AmountCents int64  `json:"amount_cents"`
	CompanyID   string `json:"company_id"`
}

type EscrowSegment struct {
	RideID       string `json:"ride_id"`
	CompanyID    string `json:"company_id"`
	DriverPubKey string `json:"driver_pub_key"`
	From         string `json:"from"`
	To           string `json:"to"`
	AmountCents  int64  `json:"amount_cents"`
}

type ReserveEscrowPayload struct {
	BookingID     string          `json:"booking_id"`
	DepartureUnix int64           `json:"departure_unix"`
	TotalCents    int64           `json:"total_cents"`
	Segments      []EscrowSegment `json:"segments"`
}

type CompleteTripPayload struct {
	BookingID string `json:"booking_id"`
}

type CancelTripPayload struct {
	BookingID string `json:"booking_id"`
	ActorRole string `json:"actor_role"` // "PASSENGER" ou "DRIVER"
	Reason    string `json:"reason,omitempty"`
}

type NoShowPayload struct {
	BookingID    string `json:"booking_id"`
	AbsentRole   string `json:"absent_role"`    // "PASSENGER" ou "DRIVER"
	AbsentPubKey string `json:"absent_pub_key"` // Chave pública de quem faltou ao embarque
	Reason       string `json:"reason,omitempty"`
}

type ReputationCategory string

const (
	RepRating          ReputationCategory = "RATING"
	RepComplaint       ReputationCategory = "COMPLAINT"
	RepLateCancel      ReputationCategory = "LATE_CANCEL"
	RepDriverCancel    ReputationCategory = "DRIVER_CANCEL"
	RepNoShowPassenger ReputationCategory = "NO_SHOW_PASSENGER"
	RepNoShowDriver    ReputationCategory = "NO_SHOW_DRIVER"
)

type ReputationPayload struct {
	BookingID    string             `json:"booking_id"`
	TargetPubKey string             `json:"target_pub_key"`
	Category     ReputationCategory `json:"category"` // "RATING" ou "COMPLAINT"
	Score        int                `json:"score"`    // 1..5 para RATING; 0 para COMPLAINT
	Comment      string             `json:"comment"`
}

// --- Votos PBFT e Blocos ---

type VotePhase string

const (
	PhasePrepare VotePhase = "PREPARE"
	PhaseCommit  VotePhase = "COMMIT"
)

// Vote representa um voto assinado de um validador nas fases PREPARE ou COMMIT do PBFT.
type Vote struct {
	Phase           VotePhase `json:"phase"`
	Height          uint64    `json:"height"`
	View            uint64    `json:"view"`
	BlockHash       string    `json:"block_hash"`
	ValidatorID     string    `json:"validator_id"`
	ValidatorPubKey string    `json:"validator_pub_key"`
	Signature       string    `json:"signature"`
}

type canonicalVoteBody struct {
	BlockHash       string    `json:"block_hash"`
	Height          uint64    `json:"height"`
	Phase           VotePhase `json:"phase"`
	ValidatorID     string    `json:"validator_id"`
	ValidatorPubKey string    `json:"validator_pub_key"`
	View            uint64    `json:"view"`
}

// CanonicalBytes retorna os bytes determinísticos do voto para assinatura/verificação.
func (v Vote) CanonicalBytes() ([]byte, error) {
	return crypto.CanonicalSerialize(canonicalVoteBody{
		BlockHash:       v.BlockHash,
		Height:          v.Height,
		Phase:           v.Phase,
		ValidatorID:     v.ValidatorID,
		ValidatorPubKey: v.ValidatorPubKey,
		View:            v.View,
	})
}

// NewSignedVote cria e assina um voto PBFT com a carteira do validador.
func NewSignedVote(w *crypto.Wallet, phase VotePhase, height, view uint64, blockHash string) (Vote, error) {
	if w == nil {
		return Vote{}, errors.New("carteira de validador nula")
	}
	v := Vote{
		Phase:           phase,
		Height:          height,
		View:            view,
		BlockHash:       blockHash,
		ValidatorID:     w.ID,
		ValidatorPubKey: w.PublicKey,
	}
	raw, err := v.CanonicalBytes()
	if err != nil {
		return Vote{}, err
	}
	sig, err := w.Sign(raw)
	if err != nil {
		return Vote{}, err
	}
	v.Signature = sig
	return v, nil
}

// Verify verifica a assinatura Ed25519 do voto.
func (v Vote) Verify() error {
	if v.Phase != PhasePrepare && v.Phase != PhaseCommit {
		return fmt.Errorf("fase de voto inválida: %s", v.Phase)
	}
	raw, err := v.CanonicalBytes()
	if err != nil {
		return err
	}
	return crypto.VerifySignature(v.ValidatorPubKey, raw, v.Signature)
}

// Block representa um bloco encadeado por SHA-256 na blockchain do consórcio.
type Block struct {
	Height        uint64        `json:"height"`
	View          uint64        `json:"view"`
	TimestampUnix int64         `json:"timestamp_unix"`
	PrevHash      string        `json:"prev_hash"`
	TxRootHash    string        `json:"tx_root_hash"`
	ProposerID    string        `json:"proposer_id"`
	Transactions  []Transaction `json:"transactions"`
	Hash          string        `json:"hash"`
	CommitVotes   []Vote        `json:"commit_votes"`
}

type canonicalBlockHeader struct {
	Height        uint64 `json:"height"`
	PrevHash      string `json:"prev_hash"`
	ProposerID    string `json:"proposer_id"`
	TimestampUnix int64  `json:"timestamp_unix"`
	TxRootHash    string `json:"tx_root_hash"`
	View          uint64 `json:"view"`
}

// ComputeTxRootHash calcula o hash determinístico da lista ordenada de transações do bloco.
func ComputeTxRootHash(txs []Transaction) (string, error) {
	if txs == nil {
		txs = []Transaction{}
	}
	raw, err := crypto.CanonicalSerialize(txs)
	if err != nil {
		return "", err
	}
	return crypto.HashSHA256(raw), nil
}

// ComputeHash calcula o SHA-256 canônico do cabeçalho do bloco.
func (b Block) ComputeHash() (string, error) {
	raw, err := crypto.CanonicalSerialize(canonicalBlockHeader{
		Height:        b.Height,
		PrevHash:      b.PrevHash,
		ProposerID:    b.ProposerID,
		TimestampUnix: b.TimestampUnix,
		TxRootHash:    b.TxRootHash,
		View:          b.View,
	})
	if err != nil {
		return "", err
	}
	return crypto.HashSHA256(raw), nil
}

// --- Estado do Ledger, Escrow, Reputação e Status P2P ---

type EscrowStatus string

const (
	EscrowLocked    EscrowStatus = "LOCKED"
	EscrowCompleted EscrowStatus = "COMPLETED"
	EscrowCancelled EscrowStatus = "CANCELLED"
	EscrowNoShow    EscrowStatus = "NO_SHOW"
)

type EscrowRecord struct {
	BookingID       string          `json:"booking_id"`
	PassengerPubKey string          `json:"passenger_pub_key"`
	DepartureUnix   int64           `json:"departure_unix"`
	TotalCents      int64           `json:"total_cents"`
	Segments        []EscrowSegment `json:"segments"`
	Status          EscrowStatus    `json:"status"`
	CreatedAtUnix   int64           `json:"created_at_unix"`
	ResolvedAtUnix  int64           `json:"resolved_at_unix,omitempty"`
	ResolutionNote  string          `json:"resolution_note,omitempty"`
}

type ReputationEntry struct {
	ID            string             `json:"id"`
	TargetPubKey  string             `json:"target_pub_key"`
	AuthorPubKey  string             `json:"author_pub_key"`
	BookingID     string             `json:"booking_id"`
	Category      ReputationCategory `json:"category"`
	Score         int                `json:"score,omitempty"`
	Comment       string             `json:"comment,omitempty"`
	TimestampUnix int64              `json:"timestamp_unix"`
	BlockHeight   uint64             `json:"block_height"`
}

// LedgerState mantém o estado derivado deterministicamente dos blocos confirmados.
type LedgerState struct {
	Balances      map[string]int64             `json:"balances"`
	Nonces        map[string]uint64            `json:"nonces"`
	Escrows       map[string]*EscrowRecord     `json:"escrows"`
	Reputations   map[string][]ReputationEntry `json:"reputations"`
	SubmittedReps map[string]bool              `json:"submitted_reps"`
	Validators    map[string]string            `json:"validators"` // pubKeyHex -> validatorID
	TotalMinted   int64                        `json:"total_minted"`
	TotalBurned   int64                        `json:"total_burned"`
}

// ChainStatus resume o topo da cadeia de um nó (retornado por GET /p2p/status).
type ChainStatus struct {
	ValidatorID string `json:"validator_id"`
	Height      uint64 `json:"height"`
	TipHash     string `json:"tip_hash"`
	View        uint64 `json:"view"`
	Corrupted   bool   `json:"corrupted,omitempty"`
}
