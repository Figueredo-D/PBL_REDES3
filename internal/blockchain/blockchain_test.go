package blockchain

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Figueredo-D/PBL_REDES/internal/crypto"
)

func setupTestValidators(t *testing.T) ([]*crypto.Wallet, map[string]string) {
	t.Helper()
	ids := []string{"SERVER_A", "SERVER_B", "SERVER_C", "SERVER_D"}
	wallets := make([]*crypto.Wallet, len(ids))
	vals := make(map[string]string, len(ids))
	for i, id := range ids {
		w, err := crypto.GenerateWallet(id, crypto.RoleValidator)
		if err != nil {
			t.Fatalf("GenerateWallet %s: %v", id, err)
		}
		wallets[i] = w
		vals[w.PublicKey] = id
	}
	return wallets, vals
}

func commitWithQuorum(t *testing.T, bc *Blockchain, validators []*crypto.Wallet, txs []Transaction, ts int64) Block {
	t.Helper()
	blk, err := bc.BuildCandidateBlock(validators[0].ID, 0, ts, txs)
	if err != nil {
		t.Fatalf("BuildCandidateBlock falhou: %v", err)
	}
	// Assina com 3 dos 4 validadores (quórum PBFT = 3/4)
	for i := 0; i < QuorumSize; i++ {
		v, err := NewSignedVote(validators[i], PhaseCommit, blk.Height, blk.View, blk.Hash)
		if err != nil {
			t.Fatalf("NewSignedVote falhou: %v", err)
		}
		blk.CommitVotes = append(blk.CommitVotes, v)
	}
	if err := bc.AppendCommittedBlock(blk); err != nil {
		t.Fatalf("AppendCommittedBlock falhou: %v", err)
	}
	return blk
}

func TestLedgerEconomyEscrowSplitAndReputation(t *testing.T) {
	tmpDir := t.TempDir()
	valWallets, valMap := setupTestValidators(t)
	chainPath := filepath.Join(tmpDir, "blockchain.json")

	bc, err := LoadOrCreateBlockchain(chainPath, valMap)
	if err != nil {
		t.Fatalf("LoadOrCreateBlockchain falhou: %v", err)
	}

	passenger, _ := crypto.GenerateWallet("Maria", crypto.RolePassenger)
	driverA, _ := crypto.GenerateWallet("MotoristaA", crypto.RoleDriver)
	driverB, _ := crypto.GenerateWallet("MotoristaB", crypto.RoleDriver)
	outsider, _ := crypto.GenerateWallet("Intruso", crypto.RolePassenger)

	// 1. Toda conta nasce com saldo 0
	if bc.BalanceOf(passenger.PublicKey) != 0 {
		t.Fatalf("esperava saldo inicial 0")
	}

	// 2. MINT por usuário comum deve ser rejeitado
	badMint, _ := NewSignedTransaction(passenger, TxMint, 1, 1700000100, MintPayload{
		TargetPubKey: passenger.PublicKey,
		AmountCents:  10000,
		CompanyID:    "SERVER_A",
		ReferenceID:  "FAKE",
	})
	if err := bc.ValidateTransaction(badMint); err == nil {
		t.Fatalf("MINT assinado por conta comum deveria ter sido rejeitado")
	}

	// 3. MINT válido assinado por SERVER_A (R$ 150,00 = 15000 centavos)
	mintTx, _ := NewSignedTransaction(valWallets[0], TxMint, 1, 1700000100, MintPayload{
		TargetPubKey: passenger.PublicKey,
		AmountCents:  15000,
		CompanyID:    "SERVER_A",
		ReferenceID:  "DEP_001",
	})
	commitWithQuorum(t, bc, valWallets, []Transaction{mintTx}, 1700000100)

	if bc.BalanceOf(passenger.PublicKey) != 15000 {
		t.Fatalf("esperava saldo 15000, obteve %d", bc.BalanceOf(passenger.PublicKey))
	}

	// 4. RESERVE_ESCROW multi-empresa (R$ 40,00 MotoristaA + R$ 60,00 MotoristaB = R$ 100,00)
	departure := int64(1700020000)
	escrowTx, _ := NewSignedTransaction(passenger, TxReserveEscrow, 1, 1700000200, ReserveEscrowPayload{
		BookingID:     "BOOK_001",
		DepartureUnix: departure,
		TotalCents:    10000,
		Segments: []EscrowSegment{
			{RideID: "R_A", CompanyID: "SERVER_A", DriverPubKey: driverA.PublicKey, From: "Salvador", To: "Feira", AmountCents: 4000},
			{RideID: "R_B", CompanyID: "SERVER_B", DriverPubKey: driverB.PublicKey, From: "Feira", To: "Conquista", AmountCents: 6000},
		},
	})
	commitWithQuorum(t, bc, valWallets, []Transaction{escrowTx}, 1700000200)

	if bc.BalanceOf(passenger.PublicKey) != 5000 {
		t.Fatalf("esperava saldo livre 5000 após escrow de 10000, obteve %d", bc.BalanceOf(passenger.PublicKey))
	}

	// 5. Tentativa de gasto duplo (tentar gastar mais 6000 quando só restam 5000) deve falhar
	doubleSpendTx, _ := NewSignedTransaction(passenger, TxReserveEscrow, 2, 1700000210, ReserveEscrowPayload{
		BookingID:     "BOOK_DOUBLE",
		DepartureUnix: departure,
		TotalCents:    6000,
		Segments: []EscrowSegment{
			{RideID: "R_A", CompanyID: "SERVER_A", DriverPubKey: driverA.PublicKey, From: "Salvador", To: "Feira", AmountCents: 6000},
		},
	})
	if err := bc.ValidateTransaction(doubleSpendTx); err == nil {
		t.Fatalf("gasto duplo deveria ter sido rejeitado")
	}

	// 6. COMPLETE_TRIP -> Split atômico entre MotoristaA (4000) e MotoristaB (6000)
	completeTx, _ := NewSignedTransaction(passenger, TxCompleteTrip, 2, 1700025000, CompleteTripPayload{
		BookingID: "BOOK_001",
	})
	commitWithQuorum(t, bc, valWallets, []Transaction{completeTx}, 1700025000)

	if bc.BalanceOf(driverA.PublicKey) != 4000 || bc.BalanceOf(driverB.PublicKey) != 6000 {
		t.Fatalf("split atômico incorreto: driverA=%d driverB=%d", bc.BalanceOf(driverA.PublicKey), bc.BalanceOf(driverB.PublicKey))
	}

	// 7. BURN pelo MotoristaA resgatando 2500 centavos
	burnTx, _ := NewSignedTransaction(driverA, TxBurn, 1, 1700026000, BurnPayload{
		AmountCents: 2500,
		CompanyID:   "SERVER_A",
	})
	commitWithQuorum(t, bc, valWallets, []Transaction{burnTx}, 1700026000)

	if bc.BalanceOf(driverA.PublicKey) != 1500 {
		t.Fatalf("esperava saldo 1500 após BURN, obteve %d", bc.BalanceOf(driverA.PublicKey))
	}

	// 8. Reputação: intruso que não viajou é rejeitado; passageiro avalia MotoristaA com sucesso; duplicata é rejeitada
	fakeRep, _ := NewSignedTransaction(outsider, TxReputation, 1, 1700027000, ReputationPayload{
		BookingID:    "BOOK_001",
		TargetPubKey: driverA.PublicKey,
		Category:     RepRating,
		Score:        1,
		Comment:      "Avaliação falsa",
	})
	if err := bc.ValidateTransaction(fakeRep); err == nil {
		t.Fatalf("avaliação por quem não viajou deveria ser rejeitada")
	}

	validRep, _ := NewSignedTransaction(passenger, TxReputation, 3, 1700027000, ReputationPayload{
		BookingID:    "BOOK_001",
		TargetPubKey: driverA.PublicKey,
		Category:     RepRating,
		Score:        5,
		Comment:      "Pontual e seguro",
	})
	commitWithQuorum(t, bc, valWallets, []Transaction{validRep}, 1700027000)

	dupRep, _ := NewSignedTransaction(passenger, TxReputation, 4, 1700027100, ReputationPayload{
		BookingID:    "BOOK_001",
		TargetPubKey: driverA.PublicKey,
		Category:     RepRating,
		Score:        4,
		Comment:      "Duplicada",
	})
	if err := bc.ValidateTransaction(dupRep); err == nil {
		t.Fatalf("avaliação duplicada deveria ser rejeitada")
	}

	// Verifica conservação de valor exata (15000 minted - 2500 burned = 5000 + 1500 + 6000 = 12500)
	snap := bc.StateSnapshot()
	if err := snap.VerifyConservation(); err != nil {
		t.Fatalf("falha na conservação de valor: %v", err)
	}
	if len(snap.Reputations[driverA.PublicKey]) != 1 {
		t.Fatalf("esperava 1 registro de reputação para driverA")
	}
}

func TestCancelRulesAndNoShowDeterministic(t *testing.T) {
	tmpDir := t.TempDir()
	valWallets, valMap := setupTestValidators(t)
	bc, err := LoadOrCreateBlockchain(filepath.Join(tmpDir, "blockchain.json"), valMap)
	if err != nil {
		t.Fatalf("LoadOrCreateBlockchain falhou: %v", err)
	}

	passenger, _ := crypto.GenerateWallet("Ana", crypto.RolePassenger)
	driver, _ := crypto.GenerateWallet("Pedro", crypto.RoleDriver)

	// Mint 30000 centavos (R$ 300,00)
	mintTx, _ := NewSignedTransaction(valWallets[0], TxMint, 1, 1700000100, MintPayload{
		TargetPubKey: passenger.PublicKey,
		AmountCents:  30000,
		CompanyID:    "SERVER_A",
		ReferenceID:  "DEP_ANA",
	})
	commitWithQuorum(t, bc, valWallets, []Transaction{mintTx}, 1700000100)

	departure := int64(1700050000)

	// Caso 1: Cancelamento pelo passageiro >= 2h antes -> 100% reembolso
	esc1, _ := NewSignedTransaction(passenger, TxReserveEscrow, 1, 1700000200, ReserveEscrowPayload{
		BookingID:     "BOOK_FREE",
		DepartureUnix: departure,
		TotalCents:    10000,
		Segments:      []EscrowSegment{{RideID: "R1", CompanyID: "SERVER_A", DriverPubKey: driver.PublicKey, From: "A", To: "B", AmountCents: 10000}},
	})
	cancelFree, _ := NewSignedTransaction(passenger, TxCancelTrip, 2, departure-FreeCancelWindowSeconds, CancelTripPayload{
		BookingID: "BOOK_FREE",
		ActorRole: "PASSENGER",
	})
	commitWithQuorum(t, bc, valWallets, []Transaction{esc1, cancelFree}, 1700042800)

	if bc.BalanceOf(passenger.PublicKey) != 30000 || bc.BalanceOf(driver.PublicKey) != 0 {
		t.Fatalf("cancelamento >=2h deveria devolver 100%%: pass=%d driver=%d", bc.BalanceOf(passenger.PublicKey), bc.BalanceOf(driver.PublicKey))
	}

	// Caso 2: Cancelamento tardio (< 2h) -> 70% passageiro (7000), 30% motorista (3000) + ocorrência LATE_CANCEL
	esc2, _ := NewSignedTransaction(passenger, TxReserveEscrow, 3, 1700000300, ReserveEscrowPayload{
		BookingID:     "BOOK_LATE",
		DepartureUnix: departure,
		TotalCents:    10000,
		Segments:      []EscrowSegment{{RideID: "R2", CompanyID: "SERVER_A", DriverPubKey: driver.PublicKey, From: "A", To: "B", AmountCents: 10000}},
	})
	cancelLate, _ := NewSignedTransaction(passenger, TxCancelTrip, 4, departure-1800, CancelTripPayload{
		BookingID: "BOOK_LATE",
		ActorRole: "PASSENGER",
		Reason:    "Imprevisto",
	})
	commitWithQuorum(t, bc, valWallets, []Transaction{esc2, cancelLate}, 1700048200)

	if bc.BalanceOf(passenger.PublicKey) != 27000 || bc.BalanceOf(driver.PublicKey) != 3000 {
		t.Fatalf("cancelamento tardio incorreto: pass=%d driver=%d", bc.BalanceOf(passenger.PublicKey), bc.BalanceOf(driver.PublicKey))
	}
	snap := bc.StateSnapshot()
	if len(snap.Reputations[passenger.PublicKey]) != 1 || snap.Reputations[passenger.PublicKey][0].Category != RepLateCancel {
		t.Fatalf("esperava registro automático de LATE_CANCEL no passageiro")
	}

	// Caso 3: No-Show do motorista -> 100% devolvido ao passageiro + ocorrência grave NO_SHOW_DRIVER
	esc3, _ := NewSignedTransaction(passenger, TxReserveEscrow, 5, 1700049000, ReserveEscrowPayload{
		BookingID:     "BOOK_NOSHOW_DRV",
		DepartureUnix: departure,
		TotalCents:    5000,
		Segments:      []EscrowSegment{{RideID: "R3", CompanyID: "SERVER_A", DriverPubKey: driver.PublicKey, From: "A", To: "B", AmountCents: 5000}},
	})
	noShowDrv, _ := NewSignedTransaction(passenger, TxNoShow, 6, departure+600, NoShowPayload{
		BookingID:    "BOOK_NOSHOW_DRV",
		AbsentRole:   "DRIVER",
		AbsentPubKey: driver.PublicKey,
		Reason:       "Motorista não compareceu",
	})
	commitWithQuorum(t, bc, valWallets, []Transaction{esc3, noShowDrv}, departure+600)

	if bc.BalanceOf(passenger.PublicKey) != 27000 {
		t.Fatalf("no-show do motorista deveria reembolsar 100%% ao passageiro, obteve %d", bc.BalanceOf(passenger.PublicKey))
	}
	snap = bc.StateSnapshot()
	if len(snap.Reputations[driver.PublicKey]) != 1 || snap.Reputations[driver.PublicKey][0].Category != RepNoShowDriver {
		t.Fatalf("esperava ocorrência NO_SHOW_DRIVER no histórico do motorista")
	}
}

func TestDetectDiskTampering(t *testing.T) {
	tmpDir := t.TempDir()
	valWallets, valMap := setupTestValidators(t)
	chainPath := filepath.Join(tmpDir, "blockchain.json")

	bc, err := LoadOrCreateBlockchain(chainPath, valMap)
	if err != nil {
		t.Fatalf("LoadOrCreateBlockchain falhou: %v", err)
	}

	passenger, _ := crypto.GenerateWallet("Lucas", crypto.RolePassenger)
	mintTx, _ := NewSignedTransaction(valWallets[0], TxMint, 1, 1700000100, MintPayload{
		TargetPubKey: passenger.PublicKey,
		AmountCents:  5000,
		CompanyID:    "SERVER_A",
		ReferenceID:  "DEP_LUCAS",
	})
	commitWithQuorum(t, bc, valWallets, []Transaction{mintTx}, 1700000100)

	// Adultera manualmente o arquivo blockchain.json em disco (5000 -> 9999)
	raw, err := os.ReadFile(chainPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	tampered := strings.Replace(string(raw), "5000", "9999", 1)
	if err := os.WriteFile(chainPath, []byte(tampered), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if err := bc.VerifyLocalIntegrity(); !errors.Is(err, ErrChainCorrupted) {
		t.Fatalf("esperava ErrChainCorrupted após adulteração manual do disco, obteve: %v", err)
	}
}
