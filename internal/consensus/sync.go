package consensus

import (
	"fmt"
	"sync"

	"github.com/Figueredo-D/PBL_REDES/internal/blockchain"
)

type peerTip struct {
	peerID  string
	peerURL string
	status  blockchain.ChainStatus
}

// SyncAndHeal executa a rotina de anti-entropia e auto-cura contra adulteração de histórico:
// 1. Re-verifica a integridade do blockchain.json local em disco.
// 2. Consulta GET /p2p/status de todos os peers em paralelo.
// 3. Se o histórico local estiver corrompido, atrasado ou divergente da maioria, baixa a cadeia
//    completa via GET /p2p/chain?from=0, valida criptograficamente TODOS os blocos e >= 3 CommitVotes,
//    substitui blockchain.json atomicamente e reconstrói LedgerState desde o bloco gênese.
func (n *PBFTNode) SyncAndHeal() (bool, error) {
	localCorrupted := n.chain.IsCorrupted()
	if err := n.chain.VerifyLocalIntegrity(); err != nil {
		localCorrupted = true
	}

	localTip := n.chain.Tip()

	// Coleta status de todos os peers em paralelo
	var wg sync.WaitGroup
	var mu sync.Mutex
	var tips []peerTip

	for peerID, peerURL := range n.peers {
		wg.Add(1)
		go func(id, url string) {
			defer wg.Done()
			st, err := n.client.GetStatus(url)
			if err != nil || st.Corrupted {
				return
			}
			mu.Lock()
			tips = append(tips, peerTip{peerID: id, peerURL: url, status: st})
			mu.Unlock()
		}(peerID, peerURL)
	}
	wg.Wait()

	if len(tips) == 0 {
		if localCorrupted {
			return false, fmt.Errorf("cadeia local corrompida e nenhum peer saudável alcançável")
		}
		return false, nil
	}

	// Agrupa peers por (Height, TipHash) para identificar a cadeia canônica da maioria
	type tipKey struct {
		height uint64
		hash   string
	}
	groups := make(map[tipKey][]peerTip)
	for _, pt := range tips {
		k := tipKey{height: pt.status.Height, hash: pt.status.TipHash}
		groups[k] = append(groups[k], pt)
	}

	var bestKey tipKey
	var bestGroup []peerTip
	for k, g := range groups {
		if len(g) > len(bestGroup) || (len(g) == len(bestGroup) && k.height > bestKey.height) {
			bestKey = k
			bestGroup = g
		}
	}

	// Se o nó local está íntegro e já bate com o topo da maioria (ou é mais alto com blocos válidos), não precisa trocar
	if !localCorrupted && localTip.Height == bestKey.height && localTip.Hash == bestKey.hash {
		return false, nil
	}
	if !localCorrupted && localTip.Height > bestKey.height {
		return false, nil
	}

	// Tenta baixar e validar criptograficamente a cadeia completa de um dos peers do grupo majoritário
	var lastErr error
	for _, pt := range bestGroup {
		blocks, err := n.client.GetChain(pt.peerURL, 0)
		if err != nil {
			lastErr = err
			continue
		}
		if err := n.chain.ReplaceChain(blocks); err != nil {
			// Se o peer enviou cadeia adulterada/sem quórum >= 3, rejeita automaticamente e tenta o próximo
			lastErr = err
			continue
		}
		return true, nil
	}

	if lastErr != nil {
		return false, fmt.Errorf("nenhum peer forneceu cadeia válida com quórum PBFT: %w", lastErr)
	}
	return false, nil
}
