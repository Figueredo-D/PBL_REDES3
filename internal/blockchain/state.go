package blockchain

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Figueredo-D/PBL_REDES/internal/crypto"
)

// NewLedgerState cria um estado limpo (saldo zero para todas as contas) com o conjunto de validadores autorizados.
func NewLedgerState(validators map[string]string) *LedgerState {
	vals := make(map[string]string, len(validators))
	for pub, id := range validators {
		vals[pub] = id
	}
	return &LedgerState{
		Balances:      make(map[string]int64),
		Nonces:        make(map[string]uint64),
		Escrows:       make(map[string]*EscrowRecord),
		Reputations:   make(map[string][]ReputationEntry),
		SubmittedReps: make(map[string]bool),
		Validators:    vals,
	}
}

// Clone faz uma cópia profunda do LedgerState para simulação segura de blocos candidatos antes do commit.
func (s *LedgerState) Clone() *LedgerState {
	c := NewLedgerState(s.Validators)
	c.TotalMinted = s.TotalMinted
	c.TotalBurned = s.TotalBurned

	for k, v := range s.Balances {
		c.Balances[k] = v
	}
	for k, v := range s.Nonces {
		c.Nonces[k] = v
	}
	for k, e := range s.Escrows {
		cp := *e
		cp.Segments = make([]EscrowSegment, len(e.Segments))
		copy(cp.Segments, e.Segments)
		c.Escrows[k] = &cp
	}
	for k, list := range s.Reputations {
		cp := make([]ReputationEntry, len(list))
		copy(cp, list)
		c.Reputations[k] = cp
	}
	for k, v := range s.SubmittedReps {
		c.SubmittedReps[k] = v
	}
	return c
}

// IsValidator retorna true se pubKeyHex pertence a uma empresa validadora autorizada.
func (s *LedgerState) IsValidator(pubKeyHex string) bool {
	_, ok := s.Validators[pubKeyHex]
	return ok
}

// VerifyConservation verifica a invariante matemática de conservação de valor:
// TotalMinted - TotalBurned == Soma(Saldos Livres) + Soma(Saldos em Escrow LOCKED).
func (s *LedgerState) VerifyConservation() error {
	var freeSum int64
	for pub, bal := range s.Balances {
		if bal < 0 {
			return fmt.Errorf("saldo negativo detectado para %s: %d", pub, bal)
		}
		freeSum += bal
	}

	var escrowSum int64
	for _, esc := range s.Escrows {
		if esc.Status == EscrowLocked {
			escrowSum += esc.TotalCents
		}
	}

	expected := s.TotalMinted - s.TotalBurned
	actual := freeSum + escrowSum
	if expected != actual {
		return fmt.Errorf("violação de conservação de valor: minted(%d)-burned(%d)=%d != livre(%d)+escrow(%d)=%d",
			s.TotalMinted, s.TotalBurned, expected, freeSum, escrowSum, actual)
	}
	return nil
}

// ValidateAndApplyTx valida criptograficamente e aplica deterministicamente uma transação ao estado.
func (s *LedgerState) ValidateAndApplyTx(tx Transaction, blockHeight uint64) error {
	if err := tx.VerifySignature(); err != nil {
		return fmt.Errorf("assinatura/integridade inválida na tx %s: %w", tx.ID, err)
	}

	expectedNonce := s.Nonces[tx.FromPubKey] + 1
	if tx.Nonce != expectedNonce {
		return fmt.Errorf("nonce inválido para %s: esperado %d, recebido %d", tx.FromPubKey, expectedNonce, tx.Nonce)
	}

	var err error
	switch tx.Type {
	case TxMint:
		err = s.applyMint(tx)
	case TxBurn:
		err = s.applyBurn(tx)
	case TxReserveEscrow:
		err = s.applyReserveEscrow(tx)
	case TxCompleteTrip:
		err = s.applyCompleteTrip(tx)
	case TxCancelTrip:
		err = s.applyCancelTrip(tx, blockHeight)
	case TxNoShow:
		err = s.applyNoShow(tx, blockHeight)
	case TxReputation:
		err = s.applyReputation(tx, blockHeight)
	default:
		return fmt.Errorf("tipo de transação desconhecido: %s", tx.Type)
	}
	if err != nil {
		return err
	}

	s.Nonces[tx.FromPubKey] = tx.Nonce
	return s.VerifyConservation()
}

func (s *LedgerState) applyMint(tx Transaction) error {
	if !s.IsValidator(tx.FromPubKey) {
		return errors.New("TX_MINT rejeitada: apenas nós validadores autorizados podem emitir créditos")
	}

	var p MintPayload
	if err := json.Unmarshal(tx.Payload, &p); err != nil {
		return fmt.Errorf("payload MINT inválido: %w", err)
	}
	if err := crypto.ValidatePublicKeyHex(p.TargetPubKey); err != nil {
		return fmt.Errorf("target_pub_key inválido no MINT: %w", err)
	}
	if p.AmountCents <= 0 {
		return errors.New("amount_cents do MINT deve ser positivo")
	}

	s.Balances[p.TargetPubKey] += p.AmountCents
	s.TotalMinted += p.AmountCents
	return nil
}

func (s *LedgerState) applyBurn(tx Transaction) error {
	var p BurnPayload
	if err := json.Unmarshal(tx.Payload, &p); err != nil {
		return fmt.Errorf("payload BURN inválido: %w", err)
	}
	if p.AmountCents <= 0 {
		return errors.New("amount_cents do BURN deve ser positivo")
	}
	if s.Balances[tx.FromPubKey] < p.AmountCents {
		return fmt.Errorf("saldo insuficiente para BURN: disponível %d, solicitado %d",
			s.Balances[tx.FromPubKey], p.AmountCents)
	}

	s.Balances[tx.FromPubKey] -= p.AmountCents
	s.TotalBurned += p.AmountCents
	return nil
}

func (s *LedgerState) applyReserveEscrow(tx Transaction) error {
	var p ReserveEscrowPayload
	if err := json.Unmarshal(tx.Payload, &p); err != nil {
		return fmt.Errorf("payload RESERVE_ESCROW inválido: %w", err)
	}
	if p.BookingID == "" {
		return errors.New("booking_id obrigatório em RESERVE_ESCROW")
	}
	if _, exists := s.Escrows[p.BookingID]; exists {
		return fmt.Errorf("escrow já existe para booking_id %s", p.BookingID)
	}
	if len(p.Segments) == 0 {
		return errors.New("RESERVE_ESCROW exige ao menos um trecho")
	}
	if p.TotalCents <= 0 {
		return errors.New("total_cents do escrow deve ser positivo")
	}

	var segSum int64
	for _, seg := range p.Segments {
		if err := crypto.ValidatePublicKeyHex(seg.DriverPubKey); err != nil {
			return fmt.Errorf("driver_pub_key inválido no trecho %s->%s: %w", seg.From, seg.To, err)
		}
		if seg.AmountCents <= 0 {
			return fmt.Errorf("valor do trecho %s->%s deve ser positivo", seg.From, seg.To)
		}
		segSum += seg.AmountCents
	}
	if segSum != p.TotalCents {
		return fmt.Errorf("soma dos trechos (%d) difere de total_cents (%d)", segSum, p.TotalCents)
	}
	if s.Balances[tx.FromPubKey] < p.TotalCents {
		return fmt.Errorf("saldo insuficiente para reserva: disponível %d, necessário %d",
			s.Balances[tx.FromPubKey], p.TotalCents)
	}

	segsCopy := make([]EscrowSegment, len(p.Segments))
	copy(segsCopy, p.Segments)

	s.Balances[tx.FromPubKey] -= p.TotalCents
	s.Escrows[p.BookingID] = &EscrowRecord{
		BookingID:       p.BookingID,
		PassengerPubKey: tx.FromPubKey,
		DepartureUnix:   p.DepartureUnix,
		TotalCents:      p.TotalCents,
		Segments:        segsCopy,
		Status:          EscrowLocked,
		CreatedAtUnix:   tx.TimestampUnix,
	}
	return nil
}

func (s *LedgerState) applyCompleteTrip(tx Transaction) error {
	var p CompleteTripPayload
	if err := json.Unmarshal(tx.Payload, &p); err != nil {
		return fmt.Errorf("payload COMPLETE_TRIP inválido: %w", err)
	}
	esc, ok := s.Escrows[p.BookingID]
	if !ok {
		return fmt.Errorf("escrow não encontrado para booking_id %s", p.BookingID)
	}
	if esc.Status != EscrowLocked {
		return fmt.Errorf("escrow %s não está LOCKED (status atual: %s)", p.BookingID, esc.Status)
	}

	// Apenas o passageiro titular ou um nó validador autorizado pode finalizar a viagem
	if tx.FromPubKey != esc.PassengerPubKey && !s.IsValidator(tx.FromPubKey) {
		return errors.New("apenas o passageiro titular ou validador autorizado pode concluir a viagem")
	}

	// Split atômico entre todos os motoristas dos trechos em uma única transição de estado
	for _, seg := range esc.Segments {
		s.Balances[seg.DriverPubKey] += seg.AmountCents
	}
	esc.Status = EscrowCompleted
	esc.ResolvedAtUnix = tx.TimestampUnix
	esc.ResolutionNote = "COMPLETED_ATOMIC_SPLIT"
	return nil
}

func (s *LedgerState) applyCancelTrip(tx Transaction, blockHeight uint64) error {
	var p CancelTripPayload
	if err := json.Unmarshal(tx.Payload, &p); err != nil {
		return fmt.Errorf("payload CANCEL_TRIP inválido: %w", err)
	}
	esc, ok := s.Escrows[p.BookingID]
	if !ok {
		return fmt.Errorf("escrow não encontrado para booking_id %s", p.BookingID)
	}
	if esc.Status != EscrowLocked {
		return fmt.Errorf("escrow %s não está LOCKED (status atual: %s)", p.BookingID, esc.Status)
	}

	switch p.ActorRole {
	case "PASSENGER":
		if tx.FromPubKey != esc.PassengerPubKey {
			return errors.New("cancelamento como PASSENGER exige assinatura do passageiro titular")
		}
		timeUntilDeparture := esc.DepartureUnix - tx.TimestampUnix
		if timeUntilDeparture >= FreeCancelWindowSeconds {
			// Cancelamento dentro do prazo (>= 2h): devolução integral de 100%
			s.Balances[esc.PassengerPubKey] += esc.TotalCents
			esc.ResolutionNote = "PASSENGER_CANCEL_FREE_100"
		} else {
			// Cancelamento tardio (< 2h): 30% distribuído aos motoristas, 70% devolvido ao passageiro + ocorrência
			var totalRetained int64
			for _, seg := range esc.Segments {
				driverShare := (seg.AmountCents * LateCancelRetentionPct) / 100
				s.Balances[seg.DriverPubKey] += driverShare
				totalRetained += driverShare
			}
			refund := esc.TotalCents - totalRetained
			s.Balances[esc.PassengerPubKey] += refund
			esc.ResolutionNote = "PASSENGER_LATE_CANCEL_70_30"

			s.appendReputationLocked(ReputationEntry{
				ID:            crypto.HashSHA256([]byte(tx.ID + ":late_cancel")),
				TargetPubKey:  esc.PassengerPubKey,
				AuthorPubKey:  tx.FromPubKey,
				BookingID:     esc.BookingID,
				Category:      RepLateCancel,
				Comment:       p.Reason,
				TimestampUnix: tx.TimestampUnix,
				BlockHeight:   blockHeight,
			})
		}

	case "DRIVER":
		if !escrowHasDriver(esc, tx.FromPubKey) {
			return errors.New("cancelamento como DRIVER exige assinatura de um motorista pertencente ao itinerário")
		}
		// Cancelamento pelo motorista: devolução de 100% ao passageiro + ocorrência no motorista
		s.Balances[esc.PassengerPubKey] += esc.TotalCents
		esc.ResolutionNote = "DRIVER_CANCEL_REFUND_100"
		s.appendReputationLocked(ReputationEntry{
			ID:            crypto.HashSHA256([]byte(tx.ID + ":driver_cancel")),
			TargetPubKey:  tx.FromPubKey,
			AuthorPubKey:  tx.FromPubKey,
			BookingID:     esc.BookingID,
			Category:      RepDriverCancel,
			Comment:       p.Reason,
			TimestampUnix: tx.TimestampUnix,
			BlockHeight:   blockHeight,
		})

	default:
		return fmt.Errorf("actor_role inválido em CANCEL_TRIP: %s", p.ActorRole)
	}

	esc.Status = EscrowCancelled
	esc.ResolvedAtUnix = tx.TimestampUnix
	return nil
}

func (s *LedgerState) applyNoShow(tx Transaction, blockHeight uint64) error {
	var p NoShowPayload
	if err := json.Unmarshal(tx.Payload, &p); err != nil {
		return fmt.Errorf("payload NO_SHOW inválido: %w", err)
	}
	esc, ok := s.Escrows[p.BookingID]
	if !ok {
		return fmt.Errorf("escrow não encontrado para booking_id %s", p.BookingID)
	}
	if esc.Status != EscrowLocked {
		return fmt.Errorf("escrow %s não está LOCKED (status atual: %s)", p.BookingID, esc.Status)
	}

	switch p.AbsentRole {
	case "PASSENGER":
		// Reportado por um motorista do itinerário ou por validador autorizado
		if !escrowHasDriver(esc, tx.FromPubKey) && !s.IsValidator(tx.FromPubKey) {
			return errors.New("ausência do passageiro só pode ser registrada por motorista do itinerário ou validador")
		}
		// 100% do valor vai para os motoristas como compensação
		for _, seg := range esc.Segments {
			s.Balances[seg.DriverPubKey] += seg.AmountCents
		}
		esc.ResolutionNote = "NO_SHOW_PASSENGER_COMPENSATED"
		s.appendReputationLocked(ReputationEntry{
			ID:            crypto.HashSHA256([]byte(tx.ID + ":no_show_passenger")),
			TargetPubKey:  esc.PassengerPubKey,
			AuthorPubKey:  tx.FromPubKey,
			BookingID:     esc.BookingID,
			Category:      RepNoShowPassenger,
			Comment:       p.Reason,
			TimestampUnix: tx.TimestampUnix,
			BlockHeight:   blockHeight,
		})

	case "DRIVER":
		// Reportado pelo passageiro titular ou por validador autorizado
		if tx.FromPubKey != esc.PassengerPubKey && !s.IsValidator(tx.FromPubKey) {
			return errors.New("ausência do motorista só pode ser registrada pelo passageiro titular ou validador")
		}
		if !escrowHasDriver(esc, p.AbsentPubKey) {
			return errors.New("absent_pub_key não pertence aos motoristas deste itinerário")
		}
		// 100% devolvido ao passageiro + ocorrência grave no motorista
		s.Balances[esc.PassengerPubKey] += esc.TotalCents
		esc.ResolutionNote = "NO_SHOW_DRIVER_REFUND_100"
		s.appendReputationLocked(ReputationEntry{
			ID:            crypto.HashSHA256([]byte(tx.ID + ":no_show_driver")),
			TargetPubKey:  p.AbsentPubKey,
			AuthorPubKey:  tx.FromPubKey,
			BookingID:     esc.BookingID,
			Category:      RepNoShowDriver,
			Comment:       p.Reason,
			TimestampUnix: tx.TimestampUnix,
			BlockHeight:   blockHeight,
		})

	default:
		return fmt.Errorf("absent_role inválido em NO_SHOW: %s", p.AbsentRole)
	}

	esc.Status = EscrowNoShow
	esc.ResolvedAtUnix = tx.TimestampUnix
	return nil
}

func (s *LedgerState) applyReputation(tx Transaction, blockHeight uint64) error {
	var p ReputationPayload
	if err := json.Unmarshal(tx.Payload, &p); err != nil {
		return fmt.Errorf("payload REPUTATION inválido: %w", err)
	}
	if p.Category != RepRating && p.Category != RepComplaint {
		return fmt.Errorf("categoria inválida para TX_REPUTATION: %s (permitido: RATING ou COMPLAINT)", p.Category)
	}
	if p.Category == RepRating && (p.Score < MinRatingScore || p.Score > MaxRatingScore) {
		return fmt.Errorf("nota de avaliação deve estar entre %d e %d", MinRatingScore, MaxRatingScore)
	}
	if p.Category == RepComplaint && p.Score != 0 {
		return errors.New("denúncia (COMPLAINT) deve ter score 0")
	}

	esc, ok := s.Escrows[p.BookingID]
	if !ok {
		return fmt.Errorf("não é possível avaliar/denunciar viagem inexistente: %s", p.BookingID)
	}
	if p.Category == RepRating && esc.Status != EscrowCompleted {
		return fmt.Errorf("avaliação (RATING) só é permitida após viagem COMPLETED (atual: %s)", esc.Status)
	}

	// Verifica participação real no itinerário: passageiro <-> motorista do mesmo booking
	authorIsPassenger := tx.FromPubKey == esc.PassengerPubKey
	authorIsDriver := escrowHasDriver(esc, tx.FromPubKey)
	targetIsPassenger := p.TargetPubKey == esc.PassengerPubKey
	targetIsDriver := escrowHasDriver(esc, p.TargetPubKey)

	if authorIsPassenger && !targetIsDriver {
		return errors.New("passageiro só pode avaliar/denunciar um motorista que participou da sua viagem")
	}
	if authorIsDriver && !targetIsPassenger {
		return errors.New("motorista só pode avaliar/denunciar o passageiro da sua viagem")
	}
	if !authorIsPassenger && !authorIsDriver {
		return errors.New("usuário não participou desta viagem e não pode lançar avaliação/denúncia")
	}

	dedupKey := fmt.Sprintf("%s|%s|%s|%s", p.BookingID, tx.FromPubKey, p.TargetPubKey, p.Category)
	if s.SubmittedReps[dedupKey] {
		return errors.New("registro de reputação duplicado para esta viagem e destinatário")
	}
	s.SubmittedReps[dedupKey] = true

	s.appendReputationLocked(ReputationEntry{
		ID:            crypto.HashSHA256([]byte(tx.ID + ":rep")),
		TargetPubKey:  p.TargetPubKey,
		AuthorPubKey:  tx.FromPubKey,
		BookingID:     p.BookingID,
		Category:      p.Category,
		Score:         p.Score,
		Comment:       p.Comment,
		TimestampUnix: tx.TimestampUnix,
		BlockHeight:   blockHeight,
	})
	return nil
}

func (s *LedgerState) appendReputationLocked(entry ReputationEntry) {
	s.Reputations[entry.TargetPubKey] = append(s.Reputations[entry.TargetPubKey], entry)
}

func escrowHasDriver(esc *EscrowRecord, driverPubKey string) bool {
	for _, seg := range esc.Segments {
		if seg.DriverPubKey == driverPubKey {
			return true
		}
	}
	return false
}
