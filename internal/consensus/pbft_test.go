package consensus

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Figueredo-D/PBL_REDES/internal/blockchain"
	"github.com/Figueredo-D/PBL_REDES/internal/crypto"
)

type memoryP2PTransport struct {
	mu       sync.RWMutex
	handlers map[string]http.Handler
	offline  map[string]bool
}

func (m *memoryP2PTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	m.mu.RLock()
	off := m.offline[req.URL.Host]
	h, ok := m.handlers[req.URL.Host]
	m.mu.RUnlock()

	if off || !ok {
		return nil, fmt.Errorf("nó %s indisponível", req.URL.Host)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Result(), nil
}

type testCluster struct {
	nodes     map[string]*PBFTNode
	wallets   map[string]*crypto.Wallet
	paths     map[string]string
	hosts     map[string]string
	transport *memoryP2PTransport
}

func setupFourNodeCluster(t *testing.T) *testCluster {
	t.Helper()
	tmpDir := t.TempDir()

	ids := []string{"SERVER_A", "SERVER_B", "SERVER_C", "SERVER_D"}
	hosts := map[string]string{
		"SERVER_A": "node-a:9080",
		"SERVER_B": "node-b:9081",
		"SERVER_C": "node-c:9082",
		"SERVER_D": "node-d:9083",
	}

	wallets := make(map[string]*crypto.Wallet, 4)
	valMap := make(map[string]string, 4)
	for _, id := range ids {
		w, err := crypto.GenerateWallet(id, crypto.RoleValidator)
		if err != nil {
			t.Fatalf("GenerateWallet %s: %v", id, err)
		}
		wallets[id] = w
		valMap[w.PublicKey] = id
	}

	transport := &memoryP2PTransport{
		handlers: make(map[string]http.Handler, 4),
		offline:  make(map[string]bool),
	}

	nodes := make(map[string]*PBFTNode, 4)
	paths := make(map[string]string, 4)

	for _, id := range ids {
		peers := make(map[string]string, 3)
		for _, other := range ids {
			if other != id {
				peers[other] = "http://" + hosts[other]
			}
		}

		p := filepath.Join(tmpDir, id, "blockchain.json")
		paths[id] = p

		bc, err := blockchain.LoadOrCreateBlockchain(p, valMap)
		if err != nil {
			t.Fatalf("LoadOrCreateBlockchain %s: %v", id, err)
		}

		node := NewPBFTNode(id, wallets[id], bc, valMap, peers)
		node.client.httpClient.Transport = transport
		nodes[id] = node

		mux := http.NewServeMux()
		node.RegisterHTTPHandlers(mux)
		transport.handlers[hosts[id]] = mux
	}

	return &testCluster{
		nodes:     nodes,
		wallets:   wallets,
		paths:     paths,
		hosts:     hosts,
		transport: transport,
	}
}

func waitHeight(t *testing.T, node *PBFTNode, target uint64) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if node.Chain().Height() >= target {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("nó %s não atingiu altura %d a tempo (atual: %d)", node.nodeID, target, node.Chain().Height())
}

func TestPBFTFourNodesConsensusAndReplication(t *testing.T) {
	c := setupFourNodeCluster(t)

	passenger, _ := crypto.GenerateWallet("Maria", crypto.RolePassenger)
	driverA, _ := crypto.GenerateWallet("DriverA", crypto.RoleDriver)
	driverB, _ := crypto.GenerateWallet("DriverB", crypto.RoleDriver)

	// 1. Submete MINT via SERVER_A (R$ 100,00)
	mintTx, _ := blockchain.NewSignedTransaction(c.wallets["SERVER_A"], blockchain.TxMint, 1, 1700001000, blockchain.MintPayload{
		TargetPubKey: passenger.PublicKey,
		AmountCents:  10000,
		CompanyID:    "SERVER_A",
		ReferenceID:  "DEP_1",
	})
	blk1, err := c.nodes["SERVER_A"].SubmitTransaction(mintTx)
	if err != nil {
		t.Fatalf("SubmitTransaction MINT falhou: %v", err)
	}
	if len(blk1.CommitVotes) < blockchain.QuorumSize {
		t.Fatalf("esperava >= %d CommitVotes, obteve %d", blockchain.QuorumSize, len(blk1.CommitVotes))
	}

	// 2. Submete RESERVE_ESCROW via SERVER_C (seguidor encaminhando ao líder)
	escrowTx, _ := blockchain.NewSignedTransaction(passenger, blockchain.TxReserveEscrow, 1, 1700001100, blockchain.ReserveEscrowPayload{
		BookingID:     "BOOK_PBFT_1",
		DepartureUnix: 1700020000,
		TotalCents:    10000,
		Segments: []blockchain.EscrowSegment{
			{RideID: "RA", CompanyID: "SERVER_A", DriverPubKey: driverA.PublicKey, From: "Salvador", To: "Feira", AmountCents: 4000},
			{RideID: "RB", CompanyID: "SERVER_B", DriverPubKey: driverB.PublicKey, From: "Feira", To: "Conquista", AmountCents: 6000},
		},
	})
	if _, err := c.nodes["SERVER_C"].SubmitTransaction(escrowTx); err != nil {
		t.Fatalf("SubmitTransaction RESERVE_ESCROW falhou: %v", err)
	}

	// 3. Submete COMPLETE_TRIP via SERVER_D -> split atômico
	completeTx, _ := blockchain.NewSignedTransaction(passenger, blockchain.TxCompleteTrip, 2, 1700025000, blockchain.CompleteTripPayload{
		BookingID: "BOOK_PBFT_1",
	})
	if _, err := c.nodes["SERVER_D"].SubmitTransaction(completeTx); err != nil {
		t.Fatalf("SubmitTransaction COMPLETE_TRIP falhou: %v", err)
	}

	// Todos os 4 nós devem convergir para a altura 3 com exatamente o mesmo hash e saldos
	for _, node := range c.nodes {
		waitHeight(t, node, 3)
	}
	refHash := c.nodes["SERVER_A"].Chain().Tip().Hash
	for id, node := range c.nodes {
		if node.Chain().Tip().Hash != refHash {
			t.Fatalf("hash divergente em %s: got=%s want=%s", id, node.Chain().Tip().Hash, refHash)
		}
		if node.Chain().BalanceOf(driverA.PublicKey) != 4000 || node.Chain().BalanceOf(driverB.PublicKey) != 6000 {
			t.Fatalf("saldos divergentes em %s", id)
		}
	}
}

func TestPBFTOperatesWithOneNodeOfflineAndSyncsOnReturn(t *testing.T) {
	c := setupFourNodeCluster(t)
	passenger, _ := crypto.GenerateWallet("Joao", crypto.RolePassenger)

	// Derruba SERVER_D (1 de 4 nós offline -> f=1)
	c.transport.mu.Lock()
	c.transport.offline[c.hosts["SERVER_D"]] = true
	c.transport.mu.Unlock()

	// Submete 2 transações com SERVER_D offline — quórum 3/4 deve aprovar normalmente
	mint1, _ := blockchain.NewSignedTransaction(c.wallets["SERVER_A"], blockchain.TxMint, 1, 1700001000, blockchain.MintPayload{
		TargetPubKey: passenger.PublicKey,
		AmountCents:  5000,
		CompanyID:    "SERVER_A",
		ReferenceID:  "DEP_OFF_1",
	})
	if _, err := c.nodes["SERVER_A"].SubmitTransaction(mint1); err != nil {
		t.Fatalf("consenso deveria funcionar com 1 nó offline (tx1): %v", err)
	}

	mint2, _ := blockchain.NewSignedTransaction(c.wallets["SERVER_B"], blockchain.TxMint, 1, 1700001100, blockchain.MintPayload{
		TargetPubKey: passenger.PublicKey,
		AmountCents:  3000,
		CompanyID:    "SERVER_B",
		ReferenceID:  "DEP_OFF_2",
	})
	if _, err := c.nodes["SERVER_C"].SubmitTransaction(mint2); err != nil {
		t.Fatalf("consenso deveria funcionar com 1 nó offline (tx2): %v", err)
	}

	waitHeight(t, c.nodes["SERVER_A"], 2)
	waitHeight(t, c.nodes["SERVER_B"], 2)
	waitHeight(t, c.nodes["SERVER_C"], 2)
	if c.nodes["SERVER_D"].Chain().Height() != 0 {
		t.Fatalf("SERVER_D estava offline e deveria estar na altura 0")
	}

	// SERVER_D volta online e sincroniza automaticamente via SyncAndHeal
	c.transport.mu.Lock()
	c.transport.offline[c.hosts["SERVER_D"]] = false
	c.transport.mu.Unlock()

	healed, err := c.nodes["SERVER_D"].SyncAndHeal()
	if err != nil || !healed {
		t.Fatalf("esperava SyncAndHeal sincronizar SERVER_D, healed=%v err=%v", healed, err)
	}
	if c.nodes["SERVER_D"].Chain().Height() != 2 || c.nodes["SERVER_D"].Chain().BalanceOf(passenger.PublicKey) != 8000 {
		t.Fatalf("SERVER_D não sincronizou corretamente: height=%d balance=%d",
			c.nodes["SERVER_D"].Chain().Height(), c.nodes["SERVER_D"].Chain().BalanceOf(passenger.PublicKey))
	}
}

func TestPBFTRejectsTamperedChainAndAutoHeals(t *testing.T) {
	c := setupFourNodeCluster(t)
	passenger, _ := crypto.GenerateWallet("Carla", crypto.RolePassenger)

	// Bloco 1 legítimo em todos os 4 nós (R$ 50,00 = 5000 centavos)
	mintTx, _ := blockchain.NewSignedTransaction(c.wallets["SERVER_A"], blockchain.TxMint, 1, 1700001000, blockchain.MintPayload{
		TargetPubKey: passenger.PublicKey,
		AmountCents:  5000,
		CompanyID:    "SERVER_A",
		ReferenceID:  "DEP_CARLA",
	})
	if _, err := c.nodes["SERVER_A"].SubmitTransaction(mintTx); err != nil {
		t.Fatalf("MINT falhou: %v", err)
	}
	for _, id := range []string{"SERVER_A", "SERVER_B", "SERVER_C", "SERVER_D"} {
		waitHeight(t, c.nodes[id], 1)
	}

	// SIMULAÇÃO DA ARGUIÇÃO: Adultera manualmente o blockchain.json do SERVER_D (5000 -> 9999)
	raw, err := os.ReadFile(c.paths["SERVER_D"])
	if err != nil {
		t.Fatalf("ReadFile SERVER_D: %v", err)
	}
	tampered := strings.Replace(string(raw), "5000", "9999", 1)
	if err := os.WriteFile(c.paths["SERVER_D"], []byte(tampered), 0o644); err != nil {
		t.Fatalf("WriteFile SERVER_D: %v", err)
	}

	// Detecta a corrupção local em disco (como ocorre no restart ou na checagem de integridade)
	if err := c.nodes["SERVER_D"].Chain().VerifyLocalIntegrity(); err == nil {
		t.Fatalf("VerifyLocalIntegrity deveria detectar adulteração em SERVER_D")
	}

	// Um bloco falso/adulterado enviado diretamente a um peer honesto deve ser rejeitado
	fakeBlock := c.nodes["SERVER_D"].Chain().Tip()
	fakeBlock.Height = 2
	fakeBlock.PrevHash = "hash_adulterado_invalido"
	if err := c.nodes["SERVER_A"].HandlePropose(fakeBlock); err == nil {
		t.Fatalf("nó honesto deveria rejeitar proposta com PrevHash adulterado")
	}

	// Mesmo com SERVER_D corrompido/isolado, os 3 nós honestos continuam operando normalmente (quórum 3/4)
	mintTx2, _ := blockchain.NewSignedTransaction(c.wallets["SERVER_B"], blockchain.TxMint, 1, 1700001200, blockchain.MintPayload{
		TargetPubKey: passenger.PublicKey,
		AmountCents:  2000,
		CompanyID:    "SERVER_B",
		ReferenceID:  "DEP_CARLA_2",
	})
	if _, err := c.nodes["SERVER_B"].SubmitTransaction(mintTx2); err != nil {
		t.Fatalf("rede honesta deveria continuar operando apesar da adulteração em SERVER_D: %v", err)
	}
	waitHeight(t, c.nodes["SERVER_A"], 2)
	waitHeight(t, c.nodes["SERVER_B"], 2)
	waitHeight(t, c.nodes["SERVER_C"], 2)

	// Rotina automática SyncAndHeal em SERVER_D detecta a adulteração e restaura a cadeia canônica da maioria
	healed, err := c.nodes["SERVER_D"].SyncAndHeal()
	if err != nil || !healed {
		t.Fatalf("SyncAndHeal deveria detectar e corrigir adulteração em SERVER_D: healed=%v err=%v", healed, err)
	}

	if err := c.nodes["SERVER_D"].Chain().VerifyLocalIntegrity(); err != nil {
		t.Fatalf("após auto-cura, blockchain.json de SERVER_D deveria estar 100%% íntegro: %v", err)
	}
	if c.nodes["SERVER_D"].Chain().BalanceOf(passenger.PublicKey) != 7000 {
		t.Fatalf("saldo após auto-cura deveria ser 7000 (5000+2000), obteve %d",
			c.nodes["SERVER_D"].Chain().BalanceOf(passenger.PublicKey))
	}
}
