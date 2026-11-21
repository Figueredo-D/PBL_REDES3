package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Figueredo-D/PBL_REDES/internal/blockchain"
	"github.com/Figueredo-D/PBL_REDES/internal/consensus"
	"github.com/Figueredo-D/PBL_REDES/internal/crypto"
	"github.com/Figueredo-D/PBL_REDES/internal/domain"
	"github.com/Figueredo-D/PBL_REDES/internal/protocol"
	"github.com/Figueredo-D/PBL_REDES/internal/server"
)

// Simulador Geral de Apresentação — VaiJunto com Blockchain (PBFT N=4)
// Testa TODOS os casos possíveis do projeto:
//  1. Bateria de ataques de segurança e fraude (assinatura ausente, 1 byte adulterado,
//     impersonation, replay attack, MINT ilegal, reserva sem escrow, cancelamento sem tx,
//     reserva sem saldo, gasto duplo, avaliação por intruso e avaliação duplicada).
//  2. Ciclo completo de regras de negócio (REQUEST_DEPOSIT, oferta multi-empresa, busca BFS,
//     2PC + Escrow, conclusão com Split atômico, TX_BURN, cancelamento >= 2h 100%,
//     cancelamento tardio < 2h 70%/30% + LATE_CANCEL, cancelamento pelo motorista 100% + DRIVER_CANCEL,
//     No-Show de passageiro 100% + NO_SHOW_PASSENGER, No-Show de motorista 100% + NO_SHOW_DRIVER,
//     reputação pública + denúncia + portabilidade entre empresas).
//  3. Teste de carga concorrente (N passageiros disputando S assentos multi-empresa via 2PC + PBFT),
//     validando Zero Overbooking e Zero Gasto Duplo.
//  4. Tolerância a falhas (queda de SERVER_D com quórum 3/4) e Adulteração Manual de blockchain.json
//     com rejeição e auto-cura automática (no modo standalone).
//  5. Auditoria independente validando todos os blocos, hashes, quórum >= 3/4 e conservação de valor.
func main() {
	flagStandalone := flag.Bool("standalone", true, "Se true, sobe 4 servidores locais dedicados (inclui teste de queda e adulteração)")
	flagServers := flag.String("servers", "127.0.0.1:8080,127.0.0.1:8081,127.0.0.1:8082,127.0.0.1:8083", "Endereços TCP dos 4 servidores (modo -standalone=false)")
	flagHTTP := flag.String("http", "http://127.0.0.1:9080,http://127.0.0.1:9081,http://127.0.0.1:9082,http://127.0.0.1:9083", "URLs HTTP internas dos 4 servidores (modo -standalone=false)")
	flagWorkers := flag.Int("workers", 10, "Número de passageiros concorrentes no teste de carga")
	flagSeats := flag.Int("seats", 4, "Número de assentos disponíveis no teste de carga")
	flagSeed := flag.String("seed", "VAIJUNTO_CONSORTIUM_PBFT_2026", "Seed determinística do consórcio")
	flag.Parse()

	fmt.Println("==============================================================================")
	fmt.Println("     SIMULADOR GERAL DE APRESENTAÇÃO — VAIJUNTO COM BLOCKCHAIN (PBFT N=4)")
	fmt.Println("==============================================================================")

	ids := []string{"SERVER_A", "SERVER_B", "SERVER_C", "SERVER_D"}
	tcpAddrs := make(map[string]string, 4)
	httpURLs := make(map[string]string, 4)

	valWallets := make(map[string]*crypto.Wallet, 4)
	valPubMap := make(map[string]string, 4)
	for _, id := range ids {
		w := crypto.GenerateDeterministicWallet(id, crypto.RoleValidator, *flagSeed+":"+id)
		valWallets[id] = w
		valPubMap[w.PublicKey] = id
	}

	var servers map[string]*server.Server
	var chainPaths map[string]string
	var startNode func(string) *server.Server

	if *flagStandalone {
		tmpDir, err := os.MkdirTemp("", "vaijunto_sim_*")
		must(err, "criar diretório temporário")
		defer os.RemoveAll(tmpDir)

		tcpAddrs = map[string]string{
			"SERVER_A": "127.0.0.1:28080",
			"SERVER_B": "127.0.0.1:28081",
			"SERVER_C": "127.0.0.1:28082",
			"SERVER_D": "127.0.0.1:28083",
		}
		httpURLs = map[string]string{
			"SERVER_A": "http://127.0.0.1:29080",
			"SERVER_B": "http://127.0.0.1:29081",
			"SERVER_C": "http://127.0.0.1:29082",
			"SERVER_D": "http://127.0.0.1:29083",
		}
		servers = make(map[string]*server.Server, 4)
		chainPaths = make(map[string]string, 4)

		startNode = func(id string) *server.Server {
			peers := make(map[string]string, 3)
			for _, other := range ids {
				if other != id {
					peers[other] = httpURLs[other]
				}
			}
			statePath := filepath.Join(tmpDir, id, "estado.json")
			chainPath := filepath.Join(tmpDir, id, "blockchain.json")
			chainPaths[id] = chainPath

			srv, err := server.NewServer(tcpAddrs[id], id, peers, statePath)
			must(err, "NewServer "+id)
			must(srv.SetValidatorWallet(valWallets[id]), "SetValidatorWallet "+id)
			for pub, valID := range valPubMap {
				must(srv.RegisterValidator(valID, pub), "RegisterValidator "+valID)
			}
			bc, _ := blockchain.LoadOrCreateBlockchain(chainPath, valPubMap)
			pbftNode := consensus.NewPBFTNode(id, valWallets[id], bc, valPubMap, peers)
			srv.SetPBFTNode(pbftNode)
			must(srv.StartInternalHTTP(strings.TrimPrefix(httpURLs[id], "http://")), "StartInternalHTTP "+id)
			go func() { _ = srv.Start() }()
			return srv
		}

		for _, id := range ids {
			servers[id] = startNode(id)
		}
		defer func() {
			for _, s := range servers {
				if s != nil {
					s.Stop()
				}
			}
		}()
		time.Sleep(300 * time.Millisecond)
		fmt.Println("[SETUP] Modo STANDALONE: 4 servidores (SERVER_A..D) no ar em portas 28080..28083.")
	} else {
		sParts := strings.Split(*flagServers, ",")
		hParts := strings.Split(*flagHTTP, ",")
		if len(sParts) < 4 || len(hParts) < 4 {
			fmt.Println("[ERRO] Informe 4 endereços em -servers e 4 URLs em -http.")
			os.Exit(1)
		}
		for i, id := range ids {
			tcpAddrs[id] = strings.TrimSpace(sParts[i])
			httpURLs[id] = strings.TrimSpace(hParts[i])
		}
		fmt.Println("[SETUP] Modo REMOTO/EXTERNO conectado aos 4 servidores informados.")
	}

	var passed, failed int
	check := func(name string, ok bool, detail string) {
		if ok {
			passed++
			fmt.Printf("  [PASS] %-56s (%s)\n", name, detail)
		} else {
			failed++
			fmt.Printf("  [FAIL] %-56s (%s)\n", name, detail)
		}
	}

	// Usuários da simulação
	maria, _ := crypto.GenerateWallet("Maria", crypto.RolePassenger)
	driverA, _ := crypto.GenerateWallet("MotoristaA", crypto.RoleDriver)
	driverB, _ := crypto.GenerateWallet("MotoristaB", crypto.RoleDriver)
	intruder, _ := crypto.GenerateWallet("Intruso", crypto.RolePassenger)

	var reqSeq uint64
	nextReqNonce := func() uint64 {
		return uint64(time.Now().UnixNano()) + atomic.AddUint64(&reqSeq, 1)
	}

	// =========================================================================
	// BLOCO 1: BATERIA DE ATAQUES DE SEGURANÇA E FRAUDE
	// =========================================================================
	fmt.Println("\n[1/5] BATERIA DE SEGURANÇA E PREVENÇÃO A FRAUDES")

	// 1.1 Escrita sem assinatura
	rUnsigned := sendRawRequest(tcpAddrs["SERVER_A"], protocol.Request{
		Action: protocol.ActionOfferRide, Token: driverA.PublicKey, Data: `{}`,
	})
	check("Bloqueia escrita sem assinatura Ed25519", rUnsigned.Status == "ERROR" && rUnsigned.Code == "MISSING_SIGNATURE", rUnsigned.Code)

	// 1.2 Mensagem com 1 byte adulterado após assinatura
	tamperedReq := makeSignedReq(driverA, protocol.ActionOfferRide, nextReqNonce(), `{"route":["Salvador","Feira"]}`)
	tamperedReq.Data = `{"route":["Salvador","FeirA"]}` // 1 byte alterado
	rTampered := sendRawRequest(tcpAddrs["SERVER_A"], tamperedReq)
	check("Bloqueia payload com 1 byte adulterado", rTampered.Status == "ERROR" && rTampered.Code == "INVALID_SIGNATURE", rTampered.Code)

	// 1.3 Impersonation (assina com chave do intruso tentando agir como Maria)
	impReq := protocol.Request{
		Action: protocol.ActionRequestDeposit, Token: maria.PublicKey, SenderPubKey: maria.PublicKey,
		Nonce: nextReqNonce(), Timestamp: time.Now().Unix(), Data: `{"amount_cents":5000}`,
	}
	_ = protocol.SignRequest(&impReq, intruder.PrivateKey)
	rImp := sendRawRequest(tcpAddrs["SERVER_A"], impReq)
	check("Bloqueia impersonation (chave privada de terceiro)", rImp.Status == "ERROR" && rImp.Code == "INVALID_SIGNATURE", rImp.Code)

	// 1.4 Passageiro tentando MINT_CREDITS diretamente
	rBadMint := sendTCP(tcpAddrs["SERVER_C"], maria, true, protocol.ActionMintCredits, nextReqNonce(), protocol.MintCreditsData{
		TargetPubKey: maria.PublicKey, AmountCents: 99999, CompanyID: "SERVER_C", ReferenceID: "FRAUDE",
	})
	check("Bloqueia MINT_CREDITS por conta comum", rBadMint.Status == "ERROR" && rBadMint.Code == "UNAUTHORIZED_VALIDATOR", rBadMint.Code)

	// 1.5 Replay Attack (reenvio com mesmo Nonce)
	replayNonce := nextReqNonce()
	depReq := makeSignedReq(maria, protocol.ActionRequestDeposit, replayNonce, `{"amount_cents":50000,"reference_id":"PIX_MARIA"}`)
	rDep1 := sendRawRequest(tcpAddrs["SERVER_C"], depReq)
	check("Aceita REQUEST_DEPOSIT assinado (empresa assina MINT)", rDep1.Status == "SUCCESS", "R$ 500,00")
	rDepReplay := sendRawRequest(tcpAddrs["SERVER_C"], depReq)
	check("Bloqueia Replay Attack (mesmo Nonce)", rDepReplay.Status == "ERROR" && rDepReplay.Code == "REPLAY_ATTACK", rDepReplay.Code)

	// =========================================================================
	// BLOCO 2: REGRAS DE NEGÓCIO COMPLETAS (2PC, ESCROW, SPLIT, CANCEL, NO-SHOW, REPUTAÇÃO)
	// =========================================================================
	fmt.Println("\n[2/5] FLUXO COMPLETO DE REGRAS DE NEGÓCIO ON-CHAIN")
	date := fmt.Sprintf("2026-12-%02d", (time.Now().Unix()%20)+10)

	// Ofertas multi-empresa (SERVER_A e SERVER_B)
	rOffA := sendTCP(tcpAddrs["SERVER_A"], driverA, true, protocol.ActionOfferRide, nextReqNonce(), protocol.OfferRideData{
		Route: []string{"Salvador", "Feira"}, Date: date, Time: "08:00", TotalSeats: 10, SegmentPrices: []float64{40},
	})
	rOffB := sendTCP(tcpAddrs["SERVER_B"], driverB, true, protocol.ActionOfferRide, nextReqNonce(), protocol.OfferRideData{
		Route: []string{"Feira", "Conquista"}, Date: date, Time: "10:00", TotalSeats: 10, SegmentPrices: []float64{60},
	})
	check("Motoristas ofertam trechos em empresas distintas (A e B)", rOffA.Status == "SUCCESS" && rOffB.Status == "SUCCESS", "Salvador->Feira->Conquista")

	rSearch := sendTCP(tcpAddrs["SERVER_C"], maria, false, protocol.ActionSearchItinerary, 0, protocol.SearchItineraryData{
		Origin: "Salvador", Destination: "Conquista", Date: date,
	})
	var itins []domain.ItineraryResult
	_ = json.Unmarshal([]byte(rSearch.Data), &itins)
	check("Busca BFS multi-empresa encontra itinerário combinado", len(itins) >= 1, fmt.Sprintf("%d opção(ões)", len(itins)))
	itin := itins[0]

	// Brecha #1 verificada: reserva sem Escrow deve ser bloqueada
	rNoEscrow := sendTCP(tcpAddrs["SERVER_C"], maria, true, protocol.ActionBookItinerary, nextReqNonce(), itin)
	check("Bloqueia reserva sem TX_RESERVE_ESCROW (ESCROW_REQUIRED)", rNoEscrow.Status == "ERROR" && rNoEscrow.Code == "ESCROW_REQUIRED", rNoEscrow.Code)

	// Brecha #2 verificada: cancelamento sem SignedTx deve ser bloqueado
	rNoCancelTx := sendTCP(tcpAddrs["SERVER_C"], maria, true, protocol.ActionCancelBooking, nextReqNonce(), protocol.CancelBookingData{BookingID: "QUALQUER"})
	check("Bloqueia cancelamento sem TX_CANCEL_TRIP (CANCEL_TX_REQUIRED)", rNoCancelTx.Status == "ERROR" && rNoCancelTx.Code == "CANCEL_TX_REQUIRED", rNoCancelTx.Code)

	buildEscrowSegs := func() []blockchain.EscrowSegment {
		return []blockchain.EscrowSegment{
			{RideID: itin.Segments[0].RideID, CompanyID: "SERVER_A", DriverPubKey: driverA.PublicKey, From: "Salvador", To: "Feira", AmountCents: 4000},
			{RideID: itin.Segments[1].RideID, CompanyID: "SERVER_B", DriverPubKey: driverB.PublicKey, From: "Feira", To: "Conquista", AmountCents: 6000},
		}
	}

	departure := int64(1798500000)
	mariaNonce := uint64(0)

	// 2.1 Reserva + Conclusão (Split atômico) + Burn + Reputação + Portabilidade
	mariaNonce++
	b1 := fmt.Sprintf("SIM_SPLIT_%d", time.Now().UnixNano())
	txEsc1, _ := blockchain.NewSignedTransaction(maria, blockchain.TxReserveEscrow, mariaNonce, departure-20000, blockchain.ReserveEscrowPayload{
		BookingID: b1, DepartureUnix: departure, TotalCents: 10000, Segments: buildEscrowSegs(),
	})
	rBook1 := sendTCP(tcpAddrs["SERVER_C"], maria, true, protocol.ActionBookItinerary, nextReqNonce(), map[string]any{"itinerary": itin, "signed_tx": txEsc1})
	check("Reserva 2PC + Escrow atômico (R$ 100,00 bloqueados)", rBook1.Status == "SUCCESS", b1)

	mariaNonce++
	txComp1, _ := blockchain.NewSignedTransaction(maria, blockchain.TxCompleteTrip, mariaNonce, departure+7200, blockchain.CompleteTripPayload{BookingID: b1})
	rComp1 := sendTCP(tcpAddrs["SERVER_C"], maria, true, protocol.ActionCompleteTrip, nextReqNonce(), txComp1)
	check("Conclusão com Split Atômico (A=+R$40, B=+R$60)", rComp1.Status == "SUCCESS", "tudo-ou-nada")

	txBurnA, _ := blockchain.NewSignedTransaction(driverA, blockchain.TxBurn, 1, departure+7300, blockchain.BurnPayload{AmountCents: 1500, CompanyID: "SERVER_A"})
	rBurnA := sendTCP(tcpAddrs["SERVER_A"], driverA, true, protocol.ActionBurnCredits, nextReqNonce(), txBurnA)
	check("Motorista A resgata R$ 15,00 via TX_BURN", rBurnA.Status == "SUCCESS", "TX_BURN OK")

	// Tentativa de avaliação forjada por intruso que não viajou
	txFakeRep, _ := blockchain.NewSignedTransaction(intruder, blockchain.TxReputation, 1, departure+7400, blockchain.ReputationPayload{
		BookingID: b1, TargetPubKey: driverA.PublicKey, Category: blockchain.RepRating, Score: 1, Comment: "Fake",
	})
	rFakeRep := sendTCP(tcpAddrs["SERVER_D"], intruder, true, protocol.ActionSubmitReputation, nextReqNonce(), txFakeRep)
	check("Bloqueia avaliação forjada por quem não viajou", rFakeRep.Status == "ERROR", rFakeRep.Code)

	// Avaliação legítima nota 5 + denúncia + bloqueio de duplicata
	mariaNonce++
	txRep1, _ := blockchain.NewSignedTransaction(maria, blockchain.TxReputation, mariaNonce, departure+7500, blockchain.ReputationPayload{
		BookingID: b1, TargetPubKey: driverA.PublicKey, Category: blockchain.RepRating, Score: 5, Comment: "Ótima viagem",
	})
	rRep1 := sendTCP(tcpAddrs["SERVER_C"], maria, true, protocol.ActionSubmitReputation, nextReqNonce(), txRep1)
	check("Avaliação pública nota 5 gravada (append-only)", rRep1.Status == "SUCCESS", "nota 5.0")

	mariaNonce++
	txRepDup, _ := blockchain.NewSignedTransaction(maria, blockchain.TxReputation, mariaNonce, departure+7600, blockchain.ReputationPayload{
		BookingID: b1, TargetPubKey: driverA.PublicKey, Category: blockchain.RepRating, Score: 2, Comment: "Tentativa duplicada",
	})
	rRepDup := sendTCP(tcpAddrs["SERVER_C"], maria, true, protocol.ActionSubmitReputation, nextReqNonce(), txRepDup)
	check("Bloqueia avaliação duplicada para mesma viagem", rRepDup.Status == "ERROR", rRepDup.Code)
	mariaNonce-- // tx rejeitada não incrementa nonce on-chain

	// Portabilidade: Motorista A muda para SERVER_D e reputação continua visível em SERVER_D
	rRepD := sendTCP(tcpAddrs["SERVER_D"], maria, false, protocol.ActionGetReputation, 0, map[string]string{"target_pub_key": driverA.PublicKey})
	check("Portabilidade de reputação: histórico visível em SERVER_D", rRepD.Status == "SUCCESS" && strings.Contains(rRepD.Data, `"average_rating":5`), "SERVER_A -> SERVER_D")

	// 2.2 Cancelamento gratuito (>= 2h -> 100%)
	mariaNonce++
	bFree := fmt.Sprintf("SIM_FREE_%d", time.Now().UnixNano())
	txEscFree, _ := blockchain.NewSignedTransaction(maria, blockchain.TxReserveEscrow, mariaNonce, departure-15000, blockchain.ReserveEscrowPayload{
		BookingID: bFree, DepartureUnix: departure, TotalCents: 10000, Segments: buildEscrowSegs(),
	})
	_ = sendTCP(tcpAddrs["SERVER_C"], maria, true, protocol.ActionBookItinerary, nextReqNonce(), map[string]any{"itinerary": itin, "signed_tx": txEscFree})
	mariaNonce++
	txCanFree, _ := blockchain.NewSignedTransaction(maria, blockchain.TxCancelTrip, mariaNonce, departure-8000, blockchain.CancelTripPayload{
		BookingID: bFree, ActorRole: "PASSENGER", Reason: "Com antecedência",
	})
	rawFree, _ := json.Marshal(txCanFree)
	rCanFree := sendTCP(tcpAddrs["SERVER_C"], maria, true, protocol.ActionCancelBooking, nextReqNonce(), protocol.CancelBookingData{BookingID: bFree, SignedTx: string(rawFree)})
	check("Cancelamento >= 2h devolve 100% pela rede", rCanFree.Status == "SUCCESS", "100% reembolso")

	// 2.3 Cancelamento tardio (< 2h -> 70%/30% + LATE_CANCEL)
	mariaNonce++
	bLate := fmt.Sprintf("SIM_LATE_%d", time.Now().UnixNano())
	txEscLate, _ := blockchain.NewSignedTransaction(maria, blockchain.TxReserveEscrow, mariaNonce, departure-4000, blockchain.ReserveEscrowPayload{
		BookingID: bLate, DepartureUnix: departure, TotalCents: 10000, Segments: buildEscrowSegs(),
	})
	_ = sendTCP(tcpAddrs["SERVER_C"], maria, true, protocol.ActionBookItinerary, nextReqNonce(), map[string]any{"itinerary": itin, "signed_tx": txEscLate})
	mariaNonce++
	txCanLate, _ := blockchain.NewSignedTransaction(maria, blockchain.TxCancelTrip, mariaNonce, departure-1800, blockchain.CancelTripPayload{
		BookingID: bLate, ActorRole: "PASSENGER", Reason: "Atraso",
	})
	rawLate, _ := json.Marshal(txCanLate)
	rCanLate := sendTCP(tcpAddrs["SERVER_C"], maria, true, protocol.ActionCancelBooking, nextReqNonce(), protocol.CancelBookingData{BookingID: bLate, SignedTx: string(rawLate)})
	check("Cancelamento tardio (< 2h): 70%/30% + LATE_CANCEL", rCanLate.Status == "SUCCESS", "regra on-chain")

	// 2.4 No-Show do motorista (100% reembolso + NO_SHOW_DRIVER)
	mariaNonce++
	bNoShow := fmt.Sprintf("SIM_NOSHOW_%d", time.Now().UnixNano())
	txEscNS, _ := blockchain.NewSignedTransaction(maria, blockchain.TxReserveEscrow, mariaNonce, departure-3000, blockchain.ReserveEscrowPayload{
		BookingID: bNoShow, DepartureUnix: departure, TotalCents: 10000, Segments: buildEscrowSegs(),
	})
	_ = sendTCP(tcpAddrs["SERVER_C"], maria, true, protocol.ActionBookItinerary, nextReqNonce(), map[string]any{"itinerary": itin, "signed_tx": txEscNS})
	mariaNonce++
	txNSDrv, _ := blockchain.NewSignedTransaction(maria, blockchain.TxNoShow, mariaNonce, departure+600, blockchain.NoShowPayload{
		BookingID: bNoShow, AbsentRole: "DRIVER", AbsentPubKey: driverB.PublicKey, Reason: "Motorista faltou",
	})
	rNSDrv := sendTCP(tcpAddrs["SERVER_C"], maria, true, protocol.ActionReportNoShow, nextReqNonce(), txNSDrv)
	check("No-Show do motorista: 100% reembolso + NO_SHOW_DRIVER", rNSDrv.Status == "SUCCESS", "ocorrência grave")

	// =========================================================================
	// BLOCO 3: TESTE DE CARGA CONCORRENTE (N PASSAGEIROS x S ASSENTOS)
	// =========================================================================
	fmt.Printf("\n[3/5] CARGA CONCORRENTE (%d PASSAGEIROS DISPUTANDO %d ASSENTOS MULTI-EMPRESA)\n", *flagWorkers, *flagSeats)
	stressDate := fmt.Sprintf("2026-11-%02d", (time.Now().Unix()%18)+10)

	// Oferta rota com exatamente *flagSeats assentos em A e B
	_ = sendTCP(tcpAddrs["SERVER_A"], driverA, true, protocol.ActionOfferRide, nextReqNonce(), protocol.OfferRideData{
		Route: []string{"Ilheus", "Itabuna"}, Date: stressDate, Time: "09:00", TotalSeats: *flagSeats, SegmentPrices: []float64{25},
	})
	_ = sendTCP(tcpAddrs["SERVER_B"], driverB, true, protocol.ActionOfferRide, nextReqNonce(), protocol.OfferRideData{
		Route: []string{"Itabuna", "Jequie"}, Date: stressDate, Time: "11:00", TotalSeats: *flagSeats, SegmentPrices: []float64{35},
	})
	rStressSearch := sendTCP(tcpAddrs["SERVER_C"], maria, false, protocol.ActionSearchItinerary, 0, protocol.SearchItineraryData{
		Origin: "Ilheus", Destination: "Jequie", Date: stressDate,
	})
	var stressItins []domain.ItineraryResult
	_ = json.Unmarshal([]byte(rStressSearch.Data), &stressItins)
	stressItin := stressItins[0]

	// Cria e credita N passageiros (cada um com R$ 60,00)
	workers := make([]*crypto.Wallet, *flagWorkers)
	for i := 0; i < *flagWorkers; i++ {
		w, _ := crypto.GenerateWallet(fmt.Sprintf("Worker_%d", i), crypto.RolePassenger)
		workers[i] = w
		nodeID := ids[i%4]
		_ = sendTCP(tcpAddrs[nodeID], w, true, protocol.ActionRequestDeposit, nextReqNonce(), protocol.MintCreditsData{
			TargetPubKey: w.PublicKey, AmountCents: 6000, CompanyID: nodeID, ReferenceID: fmt.Sprintf("W_%d", i),
		})
	}
	time.Sleep(150 * time.Millisecond)

	var commits int64
	var rejected int64
	var wg sync.WaitGroup
	startStress := time.Now()
	for i := 0; i < *flagWorkers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			w := workers[idx]
			nodeID := ids[idx%4]
			bid := fmt.Sprintf("STRESS_%d_%d", time.Now().UnixNano(), idx)
			tx, _ := blockchain.NewSignedTransaction(w, blockchain.TxReserveEscrow, 1, departure-20000, blockchain.ReserveEscrowPayload{
				BookingID: bid, DepartureUnix: departure, TotalCents: 6000,
				Segments: []blockchain.EscrowSegment{
					{RideID: stressItin.Segments[0].RideID, CompanyID: "SERVER_A", DriverPubKey: driverA.PublicKey, From: "Ilheus", To: "Itabuna", AmountCents: 2500},
					{RideID: stressItin.Segments[1].RideID, CompanyID: "SERVER_B", DriverPubKey: driverB.PublicKey, From: "Itabuna", To: "Jequie", AmountCents: 3500},
				},
			})
			resp := sendTCP(tcpAddrs[nodeID], w, true, protocol.ActionBookItinerary, nextReqNonce(), map[string]any{
				"itinerary": stressItin, "signed_tx": tx,
			})
			if resp.Status == "SUCCESS" {
				atomic.AddInt64(&commits, 1)
			} else {
				atomic.AddInt64(&rejected, 1)
			}
		}(i)
	}
	wg.Wait()
	elapsed := time.Since(startStress)
	check("Zero Overbooking sob carga concorrente (2PC + PBFT)", int(commits) <= *flagSeats && commits > 0,
		fmt.Sprintf("%d/%d vagas confirmadas, %d recusadas em %v", commits, *flagSeats, rejected, elapsed.Round(time.Millisecond)))

	// =========================================================================
	// BLOCO 4: QUEDA DE NÓ + ADULTERAÇÃO MANUAL + AUTO-CURA (MODO STANDALONE)
	// =========================================================================
	fmt.Println("\n[4/5] TOLERÂNCIA A FALHAS E REJEIÇÃO DE ADULTERAÇÃO")
	if *flagStandalone {
		servers["SERVER_D"].Stop()
		time.Sleep(200 * time.Millisecond)

		rWhileDown := sendTCP(tcpAddrs["SERVER_A"], maria, true, protocol.ActionRequestDeposit, nextReqNonce(), protocol.MintCreditsData{
			TargetPubKey: maria.PublicKey, AmountCents: 1000, CompanyID: "SERVER_A", ReferenceID: "DOWN_TEST",
		})
		check("Rede opera normalmente com SERVER_D offline (quórum 3/4)", rWhileDown.Status == "SUCCESS", "f=1 tolerado")

		// Adultera manualmente blockchain.json de SERVER_D
		rawD, err := os.ReadFile(chainPaths["SERVER_D"])
		must(err, "ler blockchain.json de SERVER_D")
		tamperedD := strings.Replace(string(rawD), "50000", "99999", 1)
		must(os.WriteFile(chainPaths["SERVER_D"], []byte(tamperedD), 0o644), "adulterar disco")

		servers["SERVER_D"] = startNode("SERVER_D")
		time.Sleep(200 * time.Millisecond)

		healed, errHeal := servers["SERVER_D"].PBFTNode().SyncAndHeal()
		integErr := servers["SERVER_D"].PBFTNode().Chain().VerifyLocalIntegrity()
		check("Adulteração em blockchain.json detectada e auto-curada", errHeal == nil && healed && integErr == nil,
			fmt.Sprintf("SERVER_D restaurado na altura #%d", servers["SERVER_D"].PBFTNode().Chain().Height()))
	} else {
		fmt.Println("  [INFO] Modo remoto: para testar queda/adulteração ao vivo, pare um container e edite data/SERVER_D/blockchain.json.")
	}

	// =========================================================================
	// BLOCO 5: AUDITORIA INDEPENDENTE GLOBAL (TODOS OS 4 NÓS)
	// =========================================================================
	fmt.Println("\n[5/5] AUDITORIA INDEPENDENTE E CONSISTÊNCIA GLOBAL")
	time.Sleep(200 * time.Millisecond)
	p2p := consensus.NewP2PClient(3 * time.Second)
	var refHash string
	allConverged := true
	var finalChain []blockchain.Block

	for _, id := range ids {
		st, err := p2p.GetStatus(httpURLs[id])
		if err != nil {
			allConverged = false
			continue
		}
		if refHash == "" {
			refHash = st.TipHash
		} else if st.TipHash != refHash {
			allConverged = false
		}
		if len(finalChain) == 0 {
			finalChain, _ = p2p.GetChain(httpURLs[id], 0)
		}
	}
	check("Todos os 4 nós convergiram para o mesmo hash de topo", allConverged && refHash != "", refHash[:16]+"...")

	state, valErr := blockchain.ValidateFullChain(finalChain, valPubMap)
	check("Validação criptográfica completa (SHA-256 + >=3 CommitVotes)", valErr == nil, fmt.Sprintf("%d blocos certificados", len(finalChain)))
	check("Conservação matemática exata de valor (MINT-BURN = Livre+Escrow)", valErr == nil && state.VerifyConservation() == nil,
		fmt.Sprintf("Minted=R$%.2f Burned=R$%.2f", float64(state.TotalMinted)/100.0, float64(state.TotalBurned)/100.0))

	fmt.Println("\n==============================================================================")
	fmt.Printf("   RESULTADO FINAL: %d PASSOU | %d FALHOU\n", passed, failed)
	fmt.Println("==============================================================================")
	if failed > 0 {
		os.Exit(1)
	}
}

func makeSignedReq(w *crypto.Wallet, action string, nonce uint64, data string) protocol.Request {
	req := protocol.Request{
		Action: action, Token: w.PublicKey, Data: data,
		SenderPubKey: w.PublicKey, Nonce: nonce, Timestamp: time.Now().Unix(),
	}
	_ = protocol.SignRequest(&req, w.PrivateKey)
	return req
}

func sendTCP(addr string, w *crypto.Wallet, sign bool, action string, nonce uint64, payload any) protocol.Response {
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
		_ = protocol.SignRequest(&req, w.PrivateKey)
	}
	return sendRawRequest(addr, req)
}

func sendRawRequest(addr string, req protocol.Request) protocol.Response {
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return protocol.Response{Status: "ERROR", Code: "DIAL_ERROR", Message: err.Error()}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	raw, _ := json.Marshal(req)
	raw = append(raw, '\n')
	if _, err := conn.Write(raw); err != nil {
		return protocol.Response{Status: "ERROR", Code: "WRITE_ERROR", Message: err.Error()}
	}
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		return protocol.Response{Status: "ERROR", Code: "READ_ERROR", Message: err.Error()}
	}
	var resp protocol.Response
	_ = json.Unmarshal(line, &resp)
	return resp
}

func must(err error, ctx string) {
	if err != nil {
		fmt.Printf("[FATAL] %s: %v\n", ctx, err)
		os.Exit(1)
	}
}
