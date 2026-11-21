package server

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/Figueredo-D/PBL_REDES/internal/blockchain"
	"github.com/Figueredo-D/PBL_REDES/internal/domain"
	"github.com/Figueredo-D/PBL_REDES/internal/protocol"
)

// ledgerTxEnvelope permite que o cliente envie uma blockchain.Transaction assinada dentro de req.Data.
type bookWithEscrowRequest struct {
	Itinerary domain.ItineraryResult  `json:"itinerary"`
	SignedTx  *blockchain.Transaction `json:"signed_tx,omitempty"`
}

func (s *Server) requirePBFT() *protocol.Response {
	if s.pbft == nil {
		return &protocol.Response{
			Status:  "ERROR",
			Code:    "BLOCKCHAIN_UNAVAILABLE",
			Message: "Camada blockchain/PBFT não inicializada neste servidor.",
		}
	}
	return nil
}

// parseAndVerifySignedTx extrai uma blockchain.Transaction de rawJSON, valida que foi assinada
// pelo mesmo autor da requisição TCP (req.SenderPubKey) e confere o tipo esperado.
func parseAndVerifySignedTx(rawJSON string, expectedType blockchain.TxType, senderPubKey string) (blockchain.Transaction, *protocol.Response) {
	var tx blockchain.Transaction
	if err := json.Unmarshal([]byte(rawJSON), &tx); err != nil {
		return tx, &protocol.Response{
			Status:  "ERROR",
			Code:    "INVALID_TX_DATA",
			Message: fmt.Sprintf("transação assinada inválida: %v", err),
		}
	}
	if tx.Type != expectedType {
		return tx, &protocol.Response{
			Status:  "ERROR",
			Code:    "TX_TYPE_MISMATCH",
			Message: fmt.Sprintf("tipo de transação esperado %s, recebido %s", expectedType, tx.Type),
		}
	}
	if senderPubKey != "" && tx.FromPubKey != senderPubKey {
		return tx, &protocol.Response{
			Status:  "ERROR",
			Code:    "IMPERSONATION_DETECTED",
			Message: "from_pub_key da transação diverge do remetente autenticado",
		}
	}
	if err := tx.VerifySignature(); err != nil {
		return tx, &protocol.Response{
			Status:  "ERROR",
			Code:    "INVALID_TX_SIGNATURE",
			Message: fmt.Sprintf("assinatura da transação blockchain inválida: %v", err),
		}
	}
	return tx, nil
}

// handleRequestDeposit recebe uma solicitação de recarga assinada pelo próprio passageiro.
// O servidor da empresa (que detém a chave privada validadora s.wallet, nunca exposta ao cliente)
// valida o depósito e assina a TX_MINT submetendo-a ao consenso PBFT.
func (s *Server) handleRequestDeposit(req protocol.Request) protocol.Response {
	if errResp := s.requirePBFT(); errResp != nil {
		return *errResp
	}
	if s.wallet == nil {
		return protocol.Response{Status: "ERROR", Code: "VALIDATOR_UNAVAILABLE", Message: "Carteira validadora da empresa não inicializada."}
	}

	var p protocol.MintCreditsData
	if err := json.Unmarshal([]byte(req.Data), &p); err != nil {
		return protocol.Response{Status: "ERROR", Code: "INVALID_DATA", Message: "Payload de depósito inválido."}
	}
	if p.AmountCents <= 0 {
		return protocol.Response{Status: "ERROR", Code: "INVALID_DATA", Message: "amount_cents deve ser maior que zero."}
	}

	target := req.SenderPubKey
	if p.TargetPubKey != "" && p.TargetPubKey != req.SenderPubKey {
		return protocol.Response{Status: "ERROR", Code: "IMPERSONATION_DETECTED", Message: "Passageiro só pode solicitar depósito para a própria carteira."}
	}

	nextNonce := s.pbft.Chain().NonceOf(s.wallet.PublicKey) + 1
	ts := req.Timestamp
	if ts <= 0 {
		ts = time.Now().Unix()
	}
	ref := p.ReferenceID
	if ref == "" {
		ref = fmt.Sprintf("DEP_%s_%d", s.id, ts)
	}

	tx, err := blockchain.NewSignedTransaction(s.wallet, blockchain.TxMint, nextNonce, ts, blockchain.MintPayload{
		TargetPubKey: target,
		AmountCents:  p.AmountCents,
		CompanyID:    s.id,
		ReferenceID:  ref,
	})
	if err != nil {
		return protocol.Response{Status: "ERROR", Code: "SIGN_FAILED", Message: err.Error()}
	}

	blk, err := s.pbft.SubmitTransaction(tx)
	if err != nil {
		return protocol.Response{Status: "ERROR", Code: "CONSENSUS_REJECTED", Message: err.Error()}
	}

	out, _ := json.Marshal(map[string]any{
		"tx_id":        tx.ID,
		"block_height": blk.Height,
		"block_hash":   blk.Hash,
		"new_balance":  s.pbft.Chain().BalanceOf(target),
	})
	return protocol.Response{
		Status:  "SUCCESS",
		Message: fmt.Sprintf("Depósito aprovado pela empresa %s e creditado no bloco #%d.", s.id, blk.Height),
		Data:    string(out),
	}
}

// handleMintCredits processa recarga de créditos (TX_MINT) assinada por um nó validador autorizado.
// Aceita tanto uma blockchain.Transaction pronta quanto protocol.MintCreditsData (assinada com s.wallet).
func (s *Server) handleMintCredits(req protocol.Request) protocol.Response {
	if errResp := s.requirePBFT(); errResp != nil {
		return *errResp
	}

	var tx blockchain.Transaction
	if err := json.Unmarshal([]byte(req.Data), &tx); err == nil && tx.Type == blockchain.TxMint && tx.Signature != "" {
		if tx.FromPubKey != req.SenderPubKey {
			return protocol.Response{Status: "ERROR", Code: "IMPERSONATION_DETECTED", Message: "MINT assinado por chave diferente do remetente."}
		}
	} else {
		var p protocol.MintCreditsData
		if err := json.Unmarshal([]byte(req.Data), &p); err != nil {
			return protocol.Response{Status: "ERROR", Code: "INVALID_DATA", Message: "Payload de MINT inválido."}
		}
		if s.wallet == nil || req.SenderPubKey != s.wallet.PublicKey {
			return protocol.Response{Status: "ERROR", Code: "UNAUTHORIZED_VALIDATOR", Message: "Apenas a empresa local pode assinar MINT sem transação pré-assinada."}
		}
		nextNonce := s.pbft.Chain().NonceOf(s.wallet.PublicKey) + 1
		ts := req.Timestamp
		if ts <= 0 {
			ts = time.Now().Unix()
		}
		var signErr error
		tx, signErr = blockchain.NewSignedTransaction(s.wallet, blockchain.TxMint, nextNonce, ts, blockchain.MintPayload{
			TargetPubKey: p.TargetPubKey,
			AmountCents:  p.AmountCents,
			CompanyID:    s.id,
			ReferenceID:  p.ReferenceID,
		})
		if signErr != nil {
			return protocol.Response{Status: "ERROR", Code: "SIGN_FAILED", Message: signErr.Error()}
		}
	}

	blk, err := s.pbft.SubmitTransaction(tx)
	if err != nil {
		return protocol.Response{Status: "ERROR", Code: "CONSENSUS_REJECTED", Message: err.Error()}
	}

	out, _ := json.Marshal(map[string]any{
		"tx_id":        tx.ID,
		"block_height": blk.Height,
		"block_hash":   blk.Hash,
	})
	return protocol.Response{
		Status:  "SUCCESS",
		Message: fmt.Sprintf("Créditos emitidos com sucesso no bloco #%d.", blk.Height),
		Data:    string(out),
	}
}

// handleBurnCredits processa resgate de créditos (TX_BURN) assinado pelo motorista titular.
func (s *Server) handleBurnCredits(req protocol.Request) protocol.Response {
	if errResp := s.requirePBFT(); errResp != nil {
		return *errResp
	}

	tx, errResp := parseAndVerifySignedTx(req.Data, blockchain.TxBurn, req.SenderPubKey)
	if errResp != nil {
		return *errResp
	}

	blk, err := s.pbft.SubmitTransaction(tx)
	if err != nil {
		return protocol.Response{Status: "ERROR", Code: "CONSENSUS_REJECTED", Message: err.Error()}
	}

	out, _ := json.Marshal(map[string]any{
		"tx_id":        tx.ID,
		"block_height": blk.Height,
		"block_hash":   blk.Hash,
		"new_balance":  s.pbft.Chain().BalanceOf(tx.FromPubKey),
	})
	return protocol.Response{
		Status:  "SUCCESS",
		Message: fmt.Sprintf("Resgate (BURN) registrado no bloco #%d.", blk.Height),
		Data:    string(out),
	}
}

// handleGetBalance retorna saldo livre, saldo bloqueado em escrow e último nonce confirmado da conta.
func (s *Server) handleGetBalance(req protocol.Request) protocol.Response {
	if errResp := s.requirePBFT(); errResp != nil {
		return *errResp
	}

	pubKey := req.Token
	if pubKey == "" {
		pubKey = req.SenderPubKey
	}
	if req.Data != "" {
		var q struct {
			PubKey string `json:"pub_key"`
		}
		if err := json.Unmarshal([]byte(req.Data), &q); err == nil && q.PubKey != "" {
			pubKey = q.PubKey
		}
	}

	snap := s.pbft.Chain().StateSnapshot()
	var lockedCents int64
	for _, esc := range snap.Escrows {
		if esc.PassengerPubKey == pubKey && esc.Status == blockchain.EscrowLocked {
			lockedCents += esc.TotalCents
		}
	}

	out, _ := json.Marshal(map[string]any{
		"pub_key":       pubKey,
		"balance_cents": snap.Balances[pubKey],
		"escrow_cents":  lockedCents,
		"nonce":         snap.Nonces[pubKey],
		"block_height":  s.pbft.Chain().Height(),
	})
	return protocol.Response{
		Status:  "SUCCESS",
		Message: "Saldo consultado na blockchain local.",
		Data:    string(out),
	}
}

// handleCompleteTrip conclui uma viagem e executa o split atômico do escrow aos motoristas na blockchain.
func (s *Server) handleCompleteTrip(req protocol.Request) protocol.Response {
	if errResp := s.requirePBFT(); errResp != nil {
		return *errResp
	}

	tx, errResp := parseAndVerifySignedTx(req.Data, blockchain.TxCompleteTrip, req.SenderPubKey)
	if errResp != nil {
		return *errResp
	}

	blk, err := s.pbft.SubmitTransaction(tx)
	if err != nil {
		return protocol.Response{Status: "ERROR", Code: "CONSENSUS_REJECTED", Message: err.Error()}
	}

	var p blockchain.CompleteTripPayload
	if err := json.Unmarshal(tx.Payload, &p); err == nil && p.BookingID != "" {
		_ = s.reqManager.Submit(func() error {
			if s.repo.UpdateBookingStatus(p.BookingID, "COMPLETED") {
				s.saveState()
			}
			return nil
		})
	}

	out, _ := json.Marshal(map[string]any{
		"tx_id":        tx.ID,
		"booking_id":   p.BookingID,
		"block_height": blk.Height,
		"block_hash":   blk.Hash,
	})
	return protocol.Response{
		Status:  "SUCCESS",
		Message: fmt.Sprintf("Viagem concluída e pagamento distribuído atomicamente no bloco #%d.", blk.Height),
		Data:    string(out),
	}
}

// handleReportNoShow registra ausência no embarque (passageiro ou motorista) on-chain.
func (s *Server) handleReportNoShow(req protocol.Request) protocol.Response {
	if errResp := s.requirePBFT(); errResp != nil {
		return *errResp
	}

	tx, errResp := parseAndVerifySignedTx(req.Data, blockchain.TxNoShow, req.SenderPubKey)
	if errResp != nil {
		return *errResp
	}

	blk, err := s.pbft.SubmitTransaction(tx)
	if err != nil {
		return protocol.Response{Status: "ERROR", Code: "CONSENSUS_REJECTED", Message: err.Error()}
	}

	var p blockchain.NoShowPayload
	if err := json.Unmarshal(tx.Payload, &p); err == nil && p.BookingID != "" {
		_ = s.reqManager.Submit(func() error {
			if s.repo.UpdateBookingStatus(p.BookingID, "NO_SHOW") {
				s.saveState()
			}
			return nil
		})
	}

	out, _ := json.Marshal(map[string]any{
		"tx_id":        tx.ID,
		"booking_id":   p.BookingID,
		"block_height": blk.Height,
		"block_hash":   blk.Hash,
	})
	return protocol.Response{
		Status:  "SUCCESS",
		Message: fmt.Sprintf("Ausência (no-show) registrada no bloco #%d.", blk.Height),
		Data:    string(out),
	}
}

// handleSubmitReputation registra uma avaliação ou denúncia imutável na blockchain.
func (s *Server) handleSubmitReputation(req protocol.Request) protocol.Response {
	if errResp := s.requirePBFT(); errResp != nil {
		return *errResp
	}

	tx, errResp := parseAndVerifySignedTx(req.Data, blockchain.TxReputation, req.SenderPubKey)
	if errResp != nil {
		return *errResp
	}

	blk, err := s.pbft.SubmitTransaction(tx)
	if err != nil {
		return protocol.Response{Status: "ERROR", Code: "CONSENSUS_REJECTED", Message: err.Error()}
	}

	out, _ := json.Marshal(map[string]any{
		"tx_id":        tx.ID,
		"block_height": blk.Height,
		"block_hash":   blk.Hash,
	})
	return protocol.Response{
		Status:  "SUCCESS",
		Message: fmt.Sprintf("Registro de reputação gravado permanentemente no bloco #%d.", blk.Height),
		Data:    string(out),
	}
}

// handleGetReputation consulta a reputação pública e histórico de ocorrências de qualquer usuário.
func (s *Server) handleGetReputation(req protocol.Request) protocol.Response {
	if errResp := s.requirePBFT(); errResp != nil {
		return *errResp
	}

	targetPubKey := req.Token
	if req.Data != "" {
		var q struct {
			PubKey       string `json:"pub_key"`
			TargetPubKey string `json:"target_pub_key"`
		}
		if err := json.Unmarshal([]byte(req.Data), &q); err == nil {
			if q.TargetPubKey != "" {
				targetPubKey = q.TargetPubKey
			} else if q.PubKey != "" {
				targetPubKey = q.PubKey
			}
		}
	}

	snap := s.pbft.Chain().StateSnapshot()
	entries := snap.Reputations[targetPubKey]
	if entries == nil {
		entries = []blockchain.ReputationEntry{}
	}
	summary := summarizeReputation(targetPubKey, entries)

	out, _ := json.Marshal(map[string]any{
		"summary": summary,
		"entries": entries,
	})
	return protocol.Response{
		Status:  "SUCCESS",
		Message: fmt.Sprintf("Encontrados %d registro(s) de reputação.", len(entries)),
		Data:    string(out),
	}
}

// handleAuditItinerary audita o ciclo de vida completo de um booking_id diretamente nos blocos da blockchain.
func (s *Server) handleAuditItinerary(req protocol.Request) protocol.Response {
	if errResp := s.requirePBFT(); errResp != nil {
		return *errResp
	}

	var q struct {
		BookingID string `json:"booking_id"`
	}
	if err := json.Unmarshal([]byte(req.Data), &q); err != nil || q.BookingID == "" {
		return protocol.Response{Status: "ERROR", Code: "INVALID_DATA", Message: "booking_id é obrigatório para auditoria."}
	}

	blocks := s.pbft.Chain().BlocksFrom(0)
	snap := s.pbft.Chain().StateSnapshot()

	type auditedTx struct {
		BlockHeight uint64                 `json:"block_height"`
		BlockHash   string                 `json:"block_hash"`
		Tx          blockchain.Transaction `json:"tx"`
	}
	var history []auditedTx
	for _, blk := range blocks {
		for _, tx := range blk.Transactions {
			var probe struct {
				BookingID string `json:"booking_id"`
			}
			if err := json.Unmarshal(tx.Payload, &probe); err == nil && probe.BookingID == q.BookingID {
				history = append(history, auditedTx{
					BlockHeight: blk.Height,
					BlockHash:   blk.Hash,
					Tx:          tx,
				})
			}
		}
	}

	var reps []blockchain.ReputationEntry
	for _, list := range snap.Reputations {
		for _, r := range list {
			if r.BookingID == q.BookingID {
				reps = append(reps, r)
			}
		}
	}

	out, _ := json.Marshal(map[string]any{
		"booking_id":      q.BookingID,
		"escrow":          snap.Escrows[q.BookingID],
		"transactions":    history,
		"reputations":     reps,
		"chain_height":    s.pbft.Chain().Height(),
		"conservation_ok": snap.VerifyConservation() == nil,
	})
	return protocol.Response{
		Status:  "SUCCESS",
		Message: fmt.Sprintf("Auditoria do itinerário %s concluída (%d transação(ões)).", q.BookingID, len(history)),
		Data:    string(out),
	}
}

// handleAuditAccount audita o saldo, escrow, extrato de transações e invariante global de conservação de valor.
func (s *Server) handleAuditAccount(req protocol.Request) protocol.Response {
	if errResp := s.requirePBFT(); errResp != nil {
		return *errResp
	}

	pubKey := req.Token
	if req.Data != "" {
		var q struct {
			PubKey string `json:"pub_key"`
		}
		if err := json.Unmarshal([]byte(req.Data), &q); err == nil && q.PubKey != "" {
			pubKey = q.PubKey
		}
	}

	blocks := s.pbft.Chain().BlocksFrom(0)
	snap := s.pbft.Chain().StateSnapshot()

	type auditedTx struct {
		BlockHeight uint64                 `json:"block_height"`
		BlockHash   string                 `json:"block_hash"`
		Tx          blockchain.Transaction `json:"tx"`
	}
	var txs []auditedTx
	for _, blk := range blocks {
		for _, tx := range blk.Transactions {
			if txInvolvesPubKey(tx, pubKey) {
				txs = append(txs, auditedTx{
					BlockHeight: blk.Height,
					BlockHash:   blk.Hash,
					Tx:          tx,
				})
			}
		}
	}

	var locked int64
	for _, esc := range snap.Escrows {
		if esc.PassengerPubKey == pubKey && esc.Status == blockchain.EscrowLocked {
			locked += esc.TotalCents
		}
	}

	out, _ := json.Marshal(map[string]any{
		"pub_key":         pubKey,
		"balance_cents":   snap.Balances[pubKey],
		"escrow_cents":    locked,
		"nonce":           snap.Nonces[pubKey],
		"total_minted":    snap.TotalMinted,
		"total_burned":    snap.TotalBurned,
		"conservation_ok": snap.VerifyConservation() == nil,
		"transactions":    txs,
		"chain_height":    s.pbft.Chain().Height(),
	})
	return protocol.Response{
		Status:  "SUCCESS",
		Message: fmt.Sprintf("Auditoria de conta concluída (%d transação(ões)).", len(txs)),
		Data:    string(out),
	}
}

// handleAuditUser audita a ficha completa de conduta/reputação e histórico de um usuário.
func (s *Server) handleAuditUser(req protocol.Request) protocol.Response {
	return s.handleGetReputation(req)
}

func summarizeReputation(pubKey string, entries []blockchain.ReputationEntry) domain.DriverReputationSummary {
	summary := domain.DriverReputationSummary{DriverPubKey: pubKey}
	var sumScore int
	for _, e := range entries {
		switch e.Category {
		case blockchain.RepRating:
			sumScore += e.Score
			summary.TotalRatings++
		case blockchain.RepComplaint:
			summary.Complaints++
		case blockchain.RepNoShowDriver, blockchain.RepNoShowPassenger:
			summary.NoShows++
		case blockchain.RepDriverCancel:
			summary.DriverCancels++
		}
	}
	if summary.TotalRatings > 0 {
		summary.AverageRating = float64(sumScore) / float64(summary.TotalRatings)
	}
	return summary
}

func (s *Server) enrichItinerariesWithReputation(itineraries []domain.ItineraryResult) {
	if s.pbft == nil {
		return
	}
	snap := s.pbft.Chain().StateSnapshot()
	for i := range itineraries {
		reps := make(map[string]domain.DriverReputationSummary)
		for _, drv := range itineraries[i].Drivers {
			reps[drv] = summarizeReputation(drv, snap.Reputations[drv])
		}
		itineraries[i].DriverReputations = reps
	}
}

func txInvolvesPubKey(tx blockchain.Transaction, pubKey string) bool {
	if tx.FromPubKey == pubKey {
		return true
	}
	switch tx.Type {
	case blockchain.TxMint:
		var p blockchain.MintPayload
		return json.Unmarshal(tx.Payload, &p) == nil && p.TargetPubKey == pubKey
	case blockchain.TxReserveEscrow:
		var p blockchain.ReserveEscrowPayload
		if json.Unmarshal(tx.Payload, &p) == nil {
			for _, seg := range p.Segments {
				if seg.DriverPubKey == pubKey {
					return true
				}
			}
		}
	case blockchain.TxReputation:
		var p blockchain.ReputationPayload
		return json.Unmarshal(tx.Payload, &p) == nil && p.TargetPubKey == pubKey
	case blockchain.TxNoShow:
		var p blockchain.NoShowPayload
		return json.Unmarshal(tx.Payload, &p) == nil && p.AbsentPubKey == pubKey
	}
	return false
}
