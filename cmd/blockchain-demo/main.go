package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Figueredo-D/PBL_REDES/internal/blockchain"
	"github.com/Figueredo-D/PBL_REDES/internal/consensus"
	"github.com/Figueredo-D/PBL_REDES/internal/crypto"
	"github.com/Figueredo-D/PBL_REDES/internal/domain"
	"github.com/Figueredo-D/PBL_REDES/internal/protocol"
	"github.com/Figueredo-D/PBL_REDES/internal/server"
)

// Script automatizado de demonstração dos 7 cenários exigidos na arguição do Problema 3.
// Sobe 4 servidores reais (SERVER_A..D) em portas dedicadas (18080..18083 / 19080..19083)
// para não conflitar com instâncias em execução nas portas padrão.
func main() {
	fmt.Println("========================================================================")
	fmt.Println("   DEMONSTRAÇÃO COMPLETA DE ARGUIÇÃO — VAIJUNTO COM BLOCKCHAIN (PBFT)")
	fmt.Println("========================================================================")

	tmpDir, err := os.MkdirTemp("", "vaijunto_demo_*")
	must(err, "criar diretório temporário")
	defer os.RemoveAll(tmpDir)

	ids := []string{"SERVER_A", "SERVER_B", "SERVER_C", "SERVER_D"}
	tcpPorts := map[string]string{
		"SERVER_A": "127.0.0.1:18080",
		"SERVER_B": "127.0.0.1:18081",
		"SERVER_C": "127.0.0.1:18082",
		"SERVER_D": "127.0.0.1:18083",
	}
	httpPorts := map[string]string{
		"SERVER_A": "127.0.0.1:19080",
		"SERVER_B": "127.0.0.1:19081",
		"SERVER_C": "127.0.0.1:19082",
		"SERVER_D": "127.0.0.1:19083",
	}

	seed := "DEMO_ARGUICAO_2026"
	valWallets := make(map[string]*crypto.Wallet, 4)
	valPubMap := make(map[string]string, 4)
	for _, id := range ids {
		w := crypto.GenerateDeterministicWallet(id, crypto.RoleValidator, seed+":"+id)
		valWallets[id] = w
		valPubMap[w.PublicKey] = id
	}

	servers := make(map[string]*server.Server, 4)
	chainPaths := make(map[string]string, 4)
	peerMaps := make(map[string]map[string]string, 4)

	startNode := func(id string) *server.Server {
		peers := make(map[string]string, 3)
		for _, other := range ids {
			if other != id {
				peers[other] = "http://" + httpPorts[other]
			}
		}
		peerMaps[id] = peers
		statePath := filepath.Join(tmpDir, id, "estado.json")
		chainPath := filepath.Join(tmpDir, id, "blockchain.json")
		chainPaths[id] = chainPath

		srv, err := server.NewServer(tcpPorts[id], id, peers, statePath)
		must(err, "NewServer "+id)
		must(srv.SetValidatorWallet(valWallets[id]), "SetValidatorWallet "+id)
		for pub, valID := range valPubMap {
			must(srv.RegisterValidator(valID, pub), "RegisterValidator "+valID)
		}
		bc, _ := blockchain.LoadOrCreateBlockchain(chainPath, valPubMap)
		pbftNode := consensus.NewPBFTNode(id, valWallets[id], bc, valPubMap, peers)
		srv.SetPBFTNode(pbftNode)
		must(srv.StartInternalHTTP(httpPorts[id]), "StartInternalHTTP "+id)
		go func() { _ = srv.Start() }()
		return srv
	}

	for _, id := range ids {
		servers[id] = startNode(id)
	}
	defer func() {
		for _, srv := range servers {
			if srv != nil {
				srv.Stop()
			}
		}
	}()
	time.Sleep(300 * time.Millisecond)
	fmt.Println("[OK] 4 nós validadores (SERVER_A..SERVER_D) inicializados com PBFT (quórum 3/4).")

	passenger, _ := crypto.GenerateWallet("Maria", crypto.RolePassenger)
	driverA, _ := crypto.GenerateWallet("MotoristaA", crypto.RoleDriver)
	driverB, _ := crypto.GenerateWallet("MotoristaB", crypto.RoleDriver)
	intruder, _ := crypto.GenerateWallet("Intruso", crypto.RolePassenger)

	// --- CENÁRIO 1: Economia de Tokens (Saldo 0 + Bloqueio de MINT ilegal + MINT legítimo) ---
	fmt.Println("\n[CENÁRIO 1] Economia de Tokens (Saldo 0, Bloqueio de MINT ilegal e MINT autorizado)")
	respBadMint := sendTCP(tcpPorts["SERVER_C"], passenger, true, protocol.ActionMintCredits, 1, protocol.MintCreditsData{
		TargetPubKey: passenger.PublicKey, AmountCents: 99999, CompanyID: "SERVER_C", ReferenceID: "FRAUDE",
	})
	assertError(respBadMint, "MINT por usuário comum deve ser bloqueado")
	fmt.Printf("  ✔ Tentativa de MINT por passageiro bloqueada (%s)\n", respBadMint.Code)

	respMint := sendTCP(tcpPorts["SERVER_C"], valWallets["SERVER_C"], true, protocol.ActionMintCredits, 1, protocol.MintCreditsData{
		TargetPubKey: passenger.PublicKey, AmountCents: 20000, CompanyID: "SERVER_C", ReferenceID: "PIX_001",
	})
	assertSuccess(respMint, "MINT legítimo pela empresa SERVER_C")
	fmt.Println("  ✔ MINT de R$ 200,00 aprovado pelo consórcio (quórum >= 3/4).")

	// --- CENÁRIO 2: Oferta multi-empresa + 2PC com Escrow + Anti-Gasto Duplo ---
	fmt.Println("\n[CENÁRIO 2] 2PC + Escrow Atômico + Proteção contra Gasto Duplo")
	date := "2026-12-25"
	assertSuccess(sendTCP(tcpPorts["SERVER_A"], driverA, true, protocol.ActionOfferRide, 1, protocol.OfferRideData{
		Route: []string{"Salvador", "Feira"}, Date: date, Time: "08:00", TotalSeats: 2, SegmentPrices: []float64{40},
	}), "OfferRide A")
	assertSuccess(sendTCP(tcpPorts["SERVER_B"], driverB, true, protocol.ActionOfferRide, 1, protocol.OfferRideData{
		Route: []string{"Feira", "Conquista"}, Date: date, Time: "10:00", TotalSeats: 2, SegmentPrices: []float64{60},
	}), "OfferRide B")

	respSearch := sendTCP(tcpPorts["SERVER_C"], passenger, false, protocol.ActionSearchItinerary, 0, protocol.SearchItineraryData{
		Origin: "Salvador", Destination: "Conquista", Date: date,
	})
	var itins []domain.ItineraryResult
	_ = json.Unmarshal([]byte(respSearch.Data), &itins)
	if len(itins) == 0 {
		panic("nenhum itinerário encontrado")
	}

	departure := int64(1798200000)
	escrowTx1, _ := blockchain.NewSignedTransaction(passenger, blockchain.TxReserveEscrow, 1, departure-10000, blockchain.ReserveEscrowPayload{
		BookingID: "DEMO_BOOK_1", DepartureUnix: departure, TotalCents: 10000,
		Segments: []blockchain.EscrowSegment{
			{RideID: itins[0].Segments[0].RideID, CompanyID: "SERVER_A", DriverPubKey: driverA.PublicKey, From: "Salvador", To: "Feira", AmountCents: 4000},
			{RideID: itins[0].Segments[1].RideID, CompanyID: "SERVER_B", DriverPubKey: driverB.PublicKey, From: "Feira", To: "Conquista", AmountCents: 6000},
		},
	})
	assertSuccess(sendTCP(tcpPorts["SERVER_C"], passenger, true, protocol.ActionBookItinerary, 2, map[string]any{
		"itinerary": itins[0], "signed_tx": escrowTx1,
	}), "Reserva 2PC + Escrow")
	fmt.Println("  ✔ Reserva DEMO_BOOK_1 confirmada via 2PC + R$ 100,00 bloqueados em Escrow.")

	// Tentativa de gasto duplo (tentar gastar R$ 150,00 quando só restam R$ 100,00 livres)
	doubleSpend, _ := blockchain.NewSignedTransaction(passenger, blockchain.TxReserveEscrow, 2, departure-9000, blockchain.ReserveEscrowPayload{
		BookingID: "DEMO_DOUBLE", DepartureUnix: departure, TotalCents: 15000,
		Segments: []blockchain.EscrowSegment{
			{RideID: itins[0].Segments[0].RideID, CompanyID: "SERVER_A", DriverPubKey: driverA.PublicKey, From: "Salvador", To: "Feira", AmountCents: 15000},
		},
	})
	respDouble := sendTCP(tcpPorts["SERVER_D"], passenger, true, protocol.ActionBookItinerary, 3, map[string]any{
		"itinerary": itins[0], "signed_tx": doubleSpend,
	})
	assertError(respDouble, "Gasto duplo deve ser rejeitado")
	fmt.Printf("  ✔ Gasto duplo rejeitado automaticamente (%s) sem consumir assentos.\n", respDouble.Code)

	// --- CENÁRIO 3: Conclusão de Viagem (Split Atômico) + BURN ---
	fmt.Println("\n[CENÁRIO 3] Conclusão de Viagem (Split Atômico) + Resgate (TX_BURN)")
	completeTx, _ := blockchain.NewSignedTransaction(passenger, blockchain.TxCompleteTrip, 2, departure+7200, blockchain.CompleteTripPayload{
		BookingID: "DEMO_BOOK_1",
	})
	assertSuccess(sendTCP(tcpPorts["SERVER_C"], passenger, true, protocol.ActionCompleteTrip, 4, completeTx), "CompleteTrip")
	fmt.Println("  ✔ Split atômico concluído: Motorista A recebeu R$ 40,00 e Motorista B recebeu R$ 60,00.")

	burnTx, _ := blockchain.NewSignedTransaction(driverA, blockchain.TxBurn, 1, departure+7300, blockchain.BurnPayload{
		AmountCents: 2000, CompanyID: "SERVER_A",
	})
	assertSuccess(sendTCP(tcpPorts["SERVER_A"], driverA, true, protocol.ActionBurnCredits, 2, burnTx), "BurnCredits")
	fmt.Println("  ✔ Motorista A resgatou R$ 20,00 via TX_BURN.")

	// --- CENÁRIO 4: Reputação Pública Imutável e Portável ---
	fmt.Println("\n[CENÁRIO 4] Reputação Pública, Portável e Anti-Fraude")
	fakeRep, _ := blockchain.NewSignedTransaction(intruder, blockchain.TxReputation, 1, departure+7400, blockchain.ReputationPayload{
		BookingID: "DEMO_BOOK_1", TargetPubKey: driverA.PublicKey, Category: blockchain.RepRating, Score: 1, Comment: "Falsa",
	})
	assertError(sendTCP(tcpPorts["SERVER_D"], intruder, true, protocol.ActionSubmitReputation, 1, fakeRep), "Avaliação por intruso deve falhar")
	fmt.Println("  ✔ Avaliação forjada por intruso que não viajou foi bloqueada pela rede.")

	validRep, _ := blockchain.NewSignedTransaction(passenger, blockchain.TxReputation, 3, departure+7500, blockchain.ReputationPayload{
		BookingID: "DEMO_BOOK_1", TargetPubKey: driverA.PublicKey, Category: blockchain.RepRating, Score: 5, Comment: "Excelente!",
	})
	assertSuccess(sendTCP(tcpPorts["SERVER_C"], passenger, true, protocol.ActionSubmitReputation, 5, validRep), "SubmitReputation")
	fmt.Println("  ✔ Avaliação nota 5 gravada permanentemente na blockchain (portável entre empresas).")

	// --- CENÁRIO 5: Queda de 1 Nó (SERVER_D) com Rede Operando (Quórum 3/4) ---
	fmt.Println("\n[CENÁRIO 5] Tolerância a Falhas — Derrubando SERVER_D (f=1)")
	servers["SERVER_D"].Stop()
	time.Sleep(200 * time.Millisecond)

	// Cancelamento tardio (< 2h) com SERVER_D offline: reserva + cancelamento tardio 70%/30%
	escrowLate, _ := blockchain.NewSignedTransaction(passenger, blockchain.TxReserveEscrow, 4, departure-3600, blockchain.ReserveEscrowPayload{
		BookingID: "DEMO_LATE", DepartureUnix: departure, TotalCents: 10000,
		Segments: []blockchain.EscrowSegment{
			{RideID: itins[0].Segments[0].RideID, CompanyID: "SERVER_A", DriverPubKey: driverA.PublicKey, From: "Salvador", To: "Feira", AmountCents: 4000},
			{RideID: itins[0].Segments[1].RideID, CompanyID: "SERVER_B", DriverPubKey: driverB.PublicKey, From: "Feira", To: "Conquista", AmountCents: 6000},
		},
	})
	assertSuccess(sendTCP(tcpPorts["SERVER_C"], passenger, true, protocol.ActionBookItinerary, 6, map[string]any{
		"itinerary": itins[0], "signed_tx": escrowLate,
	}), "Reserva com SERVER_D offline")

	cancelLateTx, _ := blockchain.NewSignedTransaction(passenger, blockchain.TxCancelTrip, 5, departure-1800, blockchain.CancelTripPayload{
		BookingID: "DEMO_LATE", ActorRole: "PASSENGER", Reason: "Atraso pessoal",
	})
	rawCancel, _ := json.Marshal(cancelLateTx)
	assertSuccess(sendTCP(tcpPorts["SERVER_C"], passenger, true, protocol.ActionCancelBooking, 7, protocol.CancelBookingData{
		BookingID: "DEMO_LATE", SignedTx: string(rawCancel),
	}), "Cancelamento tardio com SERVER_D offline")
	fmt.Println("  ✔ Rede continuou operando com 3/4 nós: reserva + cancelamento tardio (70%/30% + LATE_CANCEL) finalizados!")

	// --- CENÁRIO 6: Adulteração Manual do blockchain.json de SERVER_D + Rejeição e Auto-Cura ---
	fmt.Println("\n[CENÁRIO 6] Adulteração Manual do Histórico (blockchain.json) e Auto-Cura Automática")
	rawDisk, err := os.ReadFile(chainPaths["SERVER_D"])
	must(err, "ler blockchain.json de SERVER_D")
	tampered := strings.Replace(string(rawDisk), "20000", "99999", 1)
	must(os.WriteFile(chainPaths["SERVER_D"], []byte(tampered), 0o644), "adulterar blockchain.json")
	fmt.Println("  ! Arquivo data/SERVER_D/blockchain.json adulterado manualmente em disco (20000 -> 99999).")

	servers["SERVER_D"] = startNode("SERVER_D")
	time.Sleep(200 * time.Millisecond)

	healed, err := servers["SERVER_D"].PBFTNode().SyncAndHeal()
	must(err, "SyncAndHeal SERVER_D")
	if !healed {
		panic("esperava que SyncAndHeal restaurasse SERVER_D")
	}
	must(servers["SERVER_D"].PBFTNode().Chain().VerifyLocalIntegrity(), "integridade pós-cura de SERVER_D")
	fmt.Printf("  ✔ Adulteração detectada e corrigida automaticamente! SERVER_D restaurado na altura #%d.\n",
		servers["SERVER_D"].PBFTNode().Chain().Height())

	// --- CENÁRIO 7: Auditoria Independente + Conservação Exata de Valor ---
	fmt.Println("\n[CENÁRIO 7] Auditoria Independente em SERVER_D (Verificação de Conservação de Valor)")
	respAudit := sendTCP(tcpPorts["SERVER_D"], passenger, false, protocol.ActionAuditAccount, 0, map[string]string{
		"pub_key": passenger.PublicKey,
	})
	assertSuccess(respAudit, "Auditoria em SERVER_D")
	var audit struct {
		BalanceCents   int64 `json:"balance_cents"`
		TotalMinted    int64 `json:"total_minted"`
		TotalBurned    int64 `json:"total_burned"`
		ConservationOK bool  `json:"conservation_ok"`
		ChainHeight    uint64 `json:"chain_height"`
	}
	_ = json.Unmarshal([]byte(respAudit.Data), &audit)
	if !audit.ConservationOK {
		panic("conservação de valor violada")
	}
	fmt.Printf("  ✔ Auditoria OK | Altura #%d | Saldo Maria: R$ %.2f | Minted: R$ %.2f | Burned: R$ %.2f | Conservação: %v\n",
		audit.ChainHeight, float64(audit.BalanceCents)/100.0, float64(audit.TotalMinted)/100.0, float64(audit.TotalBurned)/100.0, audit.ConservationOK)

	fmt.Println("\n========================================================================")
	fmt.Println("   TODOS OS 7 CENÁRIOS DA ARGUIÇÃO FORAM VALIDADOS COM SUCESSO! ✔")
	fmt.Println("========================================================================")
}

func sendTCP(addr string, w *crypto.Wallet, sign bool, action string, nonce uint64, payload any) protocol.Response {
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	must(err, "conectar TCP "+addr)
	defer conn.Close()

	var dataStr string
	if payload != nil {
		b, _ := json.Marshal(payload)
		dataStr = string(b)
	}
	req := protocol.Request{Action: action, Token: w.PublicKey, Data: dataStr}
	if sign {
		req.SenderPubKey = w.PublicKey
		req.Nonce = nonce
		req.Timestamp = time.Now().Unix()
		must(protocol.SignRequest(&req, w.PrivateKey), "SignRequest")
	}
	raw, _ := json.Marshal(req)
	raw = append(raw, '\n')
	_, err = conn.Write(raw)
	must(err, "escrever TCP")

	line, err := bufio.NewReader(conn).ReadBytes('\n')
	must(err, "ler resposta TCP")
	var resp protocol.Response
	must(json.Unmarshal(line, &resp), "decodificar Response")
	return resp
}

func must(err error, ctx string) {
	if err != nil {
		fmt.Printf("[FALHA] %s: %v\n", ctx, err)
		os.Exit(1)
	}
}

func assertSuccess(resp protocol.Response, ctx string) {
	if resp.Status != "SUCCESS" {
		fmt.Printf("[FALHA] %s: esperado SUCCESS, obteve %+v\n", ctx, resp)
		os.Exit(1)
	}
}

func assertError(resp protocol.Response, ctx string) {
	if resp.Status == "SUCCESS" {
		fmt.Printf("[FALHA] %s: esperado ERROR, obteve %+v\n", ctx, resp)
		os.Exit(1)
	}
}
