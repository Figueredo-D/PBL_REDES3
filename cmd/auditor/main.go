package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Figueredo-D/PBL_REDES/internal/blockchain"
	"github.com/Figueredo-D/PBL_REDES/internal/consensus"
	"github.com/Figueredo-D/PBL_REDES/internal/crypto"
)

// Ferramenta CLI independente de auditoria da blockchain VaiJunto.
// Conecta-se diretamente aos endpoints P2P (/p2p/status e /p2p/chain) de qualquer nó,
// valida criptograficamente todos os blocos (SHA-256 + >=3 CommitVotes Ed25519 + conservação de valor)
// e permite auditar o estado global, um itinerário, uma conta ou a reputação de um usuário.
func main() {
	flagNodes := flag.String("nodes", "http://localhost:9080,http://localhost:9081,http://localhost:9082,http://localhost:9083", "URLs HTTP internas dos nós separadas por vírgula")
	flagBooking := flag.String("booking", "", "Auditar histórico completo de um booking_id")
	flagAccount := flag.String("account", "", "Auditar saldo, escrow e extrato de uma chave pública")
	flagUser := flag.String("user", "", "Auditar ficha completa de reputação de uma chave pública")
	flagSeed := flag.String("seed", "", "Seed determinística do consórcio (padrão: ENV CONSORTIUM_SEED ou VAIJUNTO_CONSORTIUM_PBFT_2026)")
	flag.Parse()

	seed := strings.TrimSpace(*flagSeed)
	if seed == "" {
		seed = strings.TrimSpace(os.Getenv("CONSORTIUM_SEED"))
	}
	if seed == "" {
		seed = "VAIJUNTO_CONSORTIUM_PBFT_2026"
	}

	knownNodes := []string{"SERVER_A", "SERVER_B", "SERVER_C", "SERVER_D"}
	validators := make(map[string]string, len(knownNodes))
	for _, id := range knownNodes {
		w := crypto.GenerateDeterministicWallet(id, crypto.RoleValidator, seed+":"+id)
		validators[w.PublicKey] = id
	}

	client := consensus.NewP2PClient(3 * time.Second)
	urls := strings.Split(*flagNodes, ",")

	fmt.Println("================================================================")
	fmt.Println("        AUDITOR INDEPENDENTE — BLOCKCHAIN VAIJUNTO (PBFT)")
	fmt.Println("================================================================")

	var bestChain []blockchain.Block
	var bestURL string

	for _, rawURL := range urls {
		u := strings.TrimSpace(rawURL)
		if u == "" {
			continue
		}
		st, err := client.GetStatus(u)
		if err != nil {
			fmt.Printf("  [OFFLINE] %-26s -> %v\n", u, err)
			continue
		}
		fmt.Printf("  [ONLINE]  %-26s -> %s | Altura: #%d | Tip: %s... | Corrompido: %v\n",
			u, st.ValidatorID, st.Height, st.TipHash[:12], st.Corrupted)

		blocks, err := client.GetChain(u, 0)
		if err != nil {
			fmt.Printf("            Erro ao baixar cadeia: %v\n", err)
			continue
		}
		if _, err := blockchain.ValidateFullChain(blocks, validators); err != nil {
			fmt.Printf("            [ALERTA] CADEIA REJEITADA NA AUDITORIA CRIPTOGRÁFICA: %v\n", err)
			continue
		}
		if len(blocks) > len(bestChain) {
			bestChain = blocks
			bestURL = u
		}
	}

	if len(bestChain) == 0 {
		fmt.Println("\n[ERRO] Nenhum nó forneceu uma cadeia criptograficamente válida.")
		os.Exit(1)
	}

	state, err := blockchain.ValidateFullChain(bestChain, validators)
	if err != nil {
		fmt.Printf("\n[ERRO] Falha na validação completa: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("----------------------------------------------------------------")
	fmt.Printf(" Cadeia Canônica Validada (fonte: %s)\n", bestURL)
	fmt.Printf("   • Blocos certificados (quórum >= 3/4): %d (altura #%d)\n", len(bestChain), bestChain[len(bestChain)-1].Height)
	fmt.Printf("   • Total Emitido (MINT):  R$ %.2f (%d centavos)\n", float64(state.TotalMinted)/100.0, state.TotalMinted)
	fmt.Printf("   • Total Resgatado (BURN): R$ %.2f (%d centavos)\n", float64(state.TotalBurned)/100.0, state.TotalBurned)
	fmt.Printf("   • Conservação de Valor:  OK (%v)\n", state.VerifyConservation() == nil)
	fmt.Println("----------------------------------------------------------------")

	if *flagBooking != "" {
		esc := state.Escrows[*flagBooking]
		b, _ := json.MarshalIndent(esc, "", "  ")
		fmt.Printf("\n[AUDITORIA DE ITINERÁRIO: %s]\n%s\n", *flagBooking, string(b))
	}
	if *flagAccount != "" {
		fmt.Printf("\n[AUDITORIA DE CONTA: %s]\n", *flagAccount)
		fmt.Printf("  Saldo Livre: R$ %.2f | Nonce: %d\n", float64(state.Balances[*flagAccount])/100.0, state.Nonces[*flagAccount])
	}
	if *flagUser != "" {
		reps := state.Reputations[*flagUser]
		b, _ := json.MarshalIndent(reps, "", "  ")
		fmt.Printf("\n[AUDITORIA DE REPUTAÇÃO: %s] (%d registro(s))\n%s\n", *flagUser, len(reps), string(b))
	}
}
