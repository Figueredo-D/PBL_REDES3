package server

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/Figueredo-D/PBL_REDES/internal/blockchain"
	"github.com/Figueredo-D/PBL_REDES/internal/consensus"
	"github.com/Figueredo-D/PBL_REDES/internal/crypto"
	"github.com/Figueredo-D/PBL_REDES/internal/domain"
	"github.com/Figueredo-D/PBL_REDES/internal/protocol"
)

func setupFourServersWithBlockchain(t *testing.T) (map[string]*Server, map[string]*crypto.Wallet, func()) {
	t.Helper()
	tmpDir := t.TempDir()

	ids := []string{"SERVER_A", "SERVER_B", "SERVER_C", "SERVER_D"}
	hosts := map[string]string{
		"SERVER_A": "bc-node-a:9080",
		"SERVER_B": "bc-node-b:9081",
		"SERVER_C": "bc-node-c:9082",
		"SERVER_D": "bc-node-d:9083",
	}

	wallets := make(map[string]*crypto.Wallet, 4)
	valMap := make(map[string]string, 4)
	for _, id := range ids {
		w := crypto.GenerateDeterministicWallet(id, crypto.RoleValidator, "TEST_SEED_2026:"+id)
		wallets[id] = w
		valMap[w.PublicKey] = id
	}

	rt := &memoryRoundTripper{
		handlers: make(map[string]http.Handler, 4),
		offline:  make(map[string]bool),
	}
	oldTransport := http.DefaultTransport
	http.DefaultTransport = rt

	servers := make(map[string]*Server, 4)
	for _, id := range ids {
		peers := make(map[string]string, 3)
		for _, other := range ids {
			if other != id {
				peers[other] = "http://" + hosts[other]
			}
		}

		srv, err := NewServer(":0", id, peers, filepath.Join(tmpDir, id, "estado.json"))
		if err != nil {
			t.Fatalf("NewServer %s: %v", id, err)
		}
		if err := srv.SetValidatorWallet(wallets[id]); err != nil {
			t.Fatalf("SetValidatorWallet %s: %v", id, err)
		}
		for pub, valID := range valMap {
			if err := srv.RegisterValidator(valID, pub); err != nil {
				t.Fatalf("RegisterValidator %s: %v", valID, err)
			}
		}

		bc, err := blockchain.LoadOrCreateBlockchain(filepath.Join(tmpDir, id, "blockchain.json"), valMap)
		if err != nil {
			t.Fatalf("LoadOrCreateBlockchain %s: %v", id, err)
		}
		pbftNode := consensus.NewPBFTNode(id, wallets[id], bc, valMap, peers)
		srv.SetPBFTNode(pbftNode)
		servers[id] = srv
		rt.handlers[hosts[id]] = srv.internalHTTPHandler()
	}

	cleanup := func() {
		http.DefaultTransport = oldTransport
	}
	return servers, wallets, cleanup
}

func TestEndToEnd2PCWithEscrowSplitReputationAndAudit(t *testing.T) {
	servers, valWallets, cleanup := setupFourServersWithBlockchain(t)
	defer cleanup()

	driverA, _ := crypto.GenerateWallet("MotoristaA", crypto.RoleDriver)
	driverB, _ := crypto.GenerateWallet("MotoristaB", crypto.RoleDriver)
	passenger, _ := crypto.GenerateWallet("Maria", crypto.RolePassenger)

	date := "2026-12-22"

	// 1. Motoristas A e B ofertam caronas em SERVER_A e SERVER_B
	respOfferA := servers["SERVER_A"].route(buildSignedRequest(t, driverA, protocol.ActionOfferRide, 1, protocol.OfferRideData{
		Route: []string{"Salvador", "Feira"}, Date: date, Time: "08:00", TotalSeats: 2, SegmentPrices: []float64{40},
	}))
	if respOfferA.Status != "SUCCESS" {
		t.Fatalf("OfferRide A falhou: %+v", respOfferA)
	}
	respOfferB := servers["SERVER_B"].route(buildSignedRequest(t, driverB, protocol.ActionOfferRide, 1, protocol.OfferRideData{
		Route: []string{"Feira", "Conquista"}, Date: date, Time: "10:00", TotalSeats: 2, SegmentPrices: []float64{60},
	}))
	if respOfferB.Status != "SUCCESS" {
		t.Fatalf("OfferRide B falhou: %+v", respOfferB)
	}

	// 2. Passageiro busca itinerário combinado em SERVER_C
	respSearch := servers["SERVER_C"].route(protocol.Request{
		Action: protocol.ActionSearchItinerary,
		Data:   `{"origin":"Salvador","destination":"Conquista","date":"` + date + `"}`,
	})
	var itins []domain.ItineraryResult
	_ = json.Unmarshal([]byte(respSearch.Data), &itins)
	if len(itins) != 1 {
		t.Fatalf("esperava 1 itinerário combinado, obteve %d", len(itins))
	}

	// 3. Passageiro tenta reservar SEM SALDO -> 2PC + Escrow deve recusar e NÃO consumir vagas!
	bookingID := "BOOK_E2E_001"
	departure := int64(1798000000)
	escrowTxNoFunds, _ := blockchain.NewSignedTransaction(passenger, blockchain.TxReserveEscrow, 1, 1797900000, blockchain.ReserveEscrowPayload{
		BookingID:     bookingID,
		DepartureUnix: departure,
		TotalCents:    10000,
		Segments: []blockchain.EscrowSegment{
			{RideID: itins[0].Segments[0].RideID, CompanyID: "SERVER_A", DriverPubKey: driverA.PublicKey, From: "Salvador", To: "Feira", AmountCents: 4000},
			{RideID: itins[0].Segments[1].RideID, CompanyID: "SERVER_B", DriverPubKey: driverB.PublicKey, From: "Feira", To: "Conquista", AmountCents: 6000},
		},
	})
	respNoFunds := servers["SERVER_C"].route(buildSignedRequest(t, passenger, protocol.ActionBookItinerary, 1, bookWithEscrowRequest{
		Itinerary: itins[0],
		SignedTx:  &escrowTxNoFunds,
	}))
	if respNoFunds.Status == "SUCCESS" {
		t.Fatalf("reserva sem saldo deveria falhar, obteve: %+v", respNoFunds)
	}

	// 4. Empresa SERVER_C faz MINT de R$ 150,00 (15000 centavos) para a passageira
	respMint := servers["SERVER_C"].route(buildSignedRequest(t, valWallets["SERVER_C"], protocol.ActionMintCredits, 1, protocol.MintCreditsData{
		TargetPubKey: passenger.PublicKey,
		AmountCents:  15000,
		CompanyID:    "SERVER_C",
		ReferenceID:  "PIX_001",
	}))
	if respMint.Status != "SUCCESS" {
		t.Fatalf("MINT falhou: %+v", respMint)
	}

	// 5. Agora a passageira reserva o itinerário com Escrow atômico + 2PC!
	respBook := servers["SERVER_C"].route(buildSignedRequest(t, passenger, protocol.ActionBookItinerary, 2, bookWithEscrowRequest{
		Itinerary: itins[0],
		SignedTx:  &escrowTxNoFunds,
	}))
	if respBook.Status != "SUCCESS" {
		t.Fatalf("reserva com saldo deveria suceder: %+v", respBook)
	}

	// Verifica saldo livre (5000) e saldo em escrow (10000) via GET_BALANCE em SERVER_D (nó que nem participou da rota!)
	time.Sleep(100 * time.Millisecond)
	respBal := servers["SERVER_D"].route(protocol.Request{
		Action: protocol.ActionGetBalance,
		Token:  passenger.PublicKey,
	})
	var balData struct {
		BalanceCents int64 `json:"balance_cents"`
		EscrowCents  int64 `json:"escrow_cents"`
	}
	_ = json.Unmarshal([]byte(respBal.Data), &balData)
	if balData.BalanceCents != 5000 || balData.EscrowCents != 10000 {
		t.Fatalf("saldo incorreto em SERVER_D: %+v", balData)
	}

	// 6. Passageira conclui a viagem -> Split atômico entre MotoristaA (4000) e MotoristaB (6000)
	completeTx, _ := blockchain.NewSignedTransaction(passenger, blockchain.TxCompleteTrip, 2, departure+7200, blockchain.CompleteTripPayload{
		BookingID: bookingID,
	})
	respComplete := servers["SERVER_C"].route(buildSignedRequest(t, passenger, protocol.ActionCompleteTrip, 3, completeTx))
	if respComplete.Status != "SUCCESS" {
		t.Fatalf("COMPLETE_TRIP falhou: %+v", respComplete)
	}

	// 7. Passageira avalia MotoristaA com nota 5
	repTx, _ := blockchain.NewSignedTransaction(passenger, blockchain.TxReputation, 3, departure+7500, blockchain.ReputationPayload{
		BookingID:    bookingID,
		TargetPubKey: driverA.PublicKey,
		Category:     blockchain.RepRating,
		Score:        5,
		Comment:      "Excelente carona",
	})
	respRep := servers["SERVER_C"].route(buildSignedRequest(t, passenger, protocol.ActionSubmitReputation, 4, repTx))
	if respRep.Status != "SUCCESS" {
		t.Fatalf("SUBMIT_REPUTATION falhou: %+v", respRep)
	}

	// 8. Nova busca em SERVER_D já exibe a reputação pública (nota 5.0) do MotoristaA!
	time.Sleep(100 * time.Millisecond)
	respSearch2 := servers["SERVER_D"].route(protocol.Request{
		Action: protocol.ActionSearchItinerary,
		Data:   `{"origin":"Salvador","destination":"Conquista","date":"` + date + `"}`,
	})
	var itins2 []domain.ItineraryResult
	_ = json.Unmarshal([]byte(respSearch2.Data), &itins2)
	if len(itins2) != 1 || itins2[0].DriverReputations[driverA.PublicKey].AverageRating != 5.0 {
		t.Fatalf("esperava reputação média 5.0 na busca de itinerários, obteve: %+v", itins2)
	}

	// 9. Auditoria independente em SERVER_D (sem depender de A, B ou C)
	respAudit := servers["SERVER_D"].route(protocol.Request{
		Action: protocol.ActionAuditItinerary,
		Data:   `{"booking_id":"` + bookingID + `"}`,
	})
	var auditData struct {
		ConservationOK bool                     `json:"conservation_ok"`
		Transactions   []map[string]any         `json:"transactions"`
		Escrow         *blockchain.EscrowRecord `json:"escrow"`
	}
	_ = json.Unmarshal([]byte(respAudit.Data), &auditData)
	if !auditData.ConservationOK || auditData.Escrow == nil || auditData.Escrow.Status != blockchain.EscrowCompleted || len(auditData.Transactions) != 3 {
		t.Fatalf("auditoria independente divergente: %+v", auditData)
	}
}
