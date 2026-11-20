package consensus

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/Figueredo-D/PBL_REDES/internal/blockchain"
	"github.com/Figueredo-D/PBL_REDES/internal/crypto"
)

// PBFTNode coordena o consenso PBFT simplificado em 3 fases (Propose, Prepare, Commit)
// entre os N=4 validadores do consórcio (quórum >= 3/4, tolerando f=1 nó offline ou malicioso).
type PBFTNode struct {
	mu             sync.Mutex
	proposeMu      sync.Mutex // serializa propostas iniciadas por este nó para evitar conflito de altura
	nodeID         string
	wallet         *crypto.Wallet
	chain          *blockchain.Blockchain
	validators     map[string]string // pubKeyHex -> validatorID
	validatorOrder []string          // IDs ordenados deterministicamente (ex: SERVER_A..SERVER_D)
	peers          map[string]string // peerID -> baseURL (http://host:908X)
	client         *P2PClient

	view           uint64
	pendingBlocks  map[string]blockchain.Block              // blockHash -> bloco candidato validado
	prepareVotes   map[string]map[string]blockchain.Vote    // blockHash -> validatorPubKey -> Vote
	commitVotes    map[string]map[string]blockchain.Vote    // blockHash -> validatorPubKey -> Vote
	sentPrepare    map[string]bool                          // blockHash -> já enviou PREPARE
	sentCommit     map[string]bool                          // blockHash -> já enviou COMMIT
	committedHash  map[string]bool                          // blockHash -> já aplicado à chain
	waiters        map[string][]chan blockchain.Block       // blockHash -> canais aguardando finalização
	roundTimeout   time.Duration
}

// NewPBFTNode inicializa um nó PBFT acoplado à sua blockchain local e carteira Ed25519.
func NewPBFTNode(
	nodeID string,
	wallet *crypto.Wallet,
	chain *blockchain.Blockchain,
	validators map[string]string,
	peers map[string]string,
) *PBFTNode {
	valCopy := make(map[string]string, len(validators))
	idSet := make(map[string]bool)
	for pub, id := range validators {
		valCopy[pub] = id
		idSet[id] = true
	}
	order := make([]string, 0, len(idSet))
	for id := range idSet {
		order = append(order, id)
	}
	sort.Strings(order)

	peerCopy := make(map[string]string, len(peers))
	for id, url := range peers {
		if id != nodeID {
			peerCopy[id] = url
		}
	}

	return &PBFTNode{
		nodeID:         nodeID,
		wallet:         wallet,
		chain:          chain,
		validators:     valCopy,
		validatorOrder: order,
		peers:          peerCopy,
		client:         NewP2PClient(3 * time.Second),
		pendingBlocks:  make(map[string]blockchain.Block),
		prepareVotes:   make(map[string]map[string]blockchain.Vote),
		commitVotes:    make(map[string]map[string]blockchain.Vote),
		sentPrepare:    make(map[string]bool),
		sentCommit:     make(map[string]bool),
		committedHash:  make(map[string]bool),
		waiters:        make(map[string][]chan blockchain.Block),
		roundTimeout:   5 * time.Second,
	}
}

// Chain retorna a blockchain local gerenciada por este nó PBFT.
func (n *PBFTNode) Chain() *blockchain.Blockchain {
	return n.chain
}

// LeaderFor escolhe deterministicamente o líder para (height, view).
func (n *PBFTNode) LeaderFor(height, view uint64) string {
	if len(n.validatorOrder) == 0 {
		return n.nodeID
	}
	idx := (height + view) % uint64(len(n.validatorOrder))
	return n.validatorOrder[idx]
}

// Status retorna o resumo atual da cadeia local (usado em GET /p2p/status).
func (n *PBFTNode) Status() blockchain.ChainStatus {
	tip := n.chain.Tip()
	n.mu.Lock()
	view := n.view
	n.mu.Unlock()

	return blockchain.ChainStatus{
		ValidatorID: n.nodeID,
		Height:      tip.Height,
		TipHash:     tip.Hash,
		View:        view,
		Corrupted:   n.chain.IsCorrupted(),
	}
}

// SubmitTransaction submete uma transação assinada ao consenso PBFT.
// Se este nó for o líder da view atual, inicia a rodada; caso contrário encaminha ao líder.
// Se o líder atual estiver offline, faz view-change automático tentando os próximos líderes.
func (n *PBFTNode) SubmitTransaction(tx blockchain.Transaction) (blockchain.Block, error) {
	if n.chain.IsCorrupted() {
		if _, err := n.SyncAndHeal(); err != nil {
			return blockchain.Block{}, fmt.Errorf("cadeia local corrompida e falha ao ressincronizar: %w", err)
		}
	}

	if err := n.chain.ValidateTransaction(tx); err != nil {
		return blockchain.Block{}, fmt.Errorf("transação inválida: %w", err)
	}

	maxAttempts := len(n.validatorOrder)
	if maxAttempts == 0 {
		maxAttempts = 1
	}

	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		nextHeight := n.chain.Height() + 1
		n.mu.Lock()
		view := n.view
		n.mu.Unlock()

		leaderID := n.LeaderFor(nextHeight, view)
		if leaderID == n.nodeID {
			block, err := n.proposeAsLeader([]blockchain.Transaction{tx}, view)
			if err == nil {
				return block, nil
			}
			lastErr = err
		} else {
			peerURL, ok := n.peers[leaderID]
			if ok {
				block, err := n.client.ForwardTx(peerURL, tx)
				if err == nil {
					// Garante que este nó também já tenha o bloco finalizado localmente
					if errAppend := n.chain.AppendCommittedBlock(block); errAppend != nil {
						_, _ = n.SyncAndHeal()
					}
					return block, nil
				}
				lastErr = err
			} else {
				lastErr = fmt.Errorf("líder %s não encontrado na lista de peers", leaderID)
			}
		}

		// Líder indisponível ou falhou: avança a view (view-change determinístico)
		n.mu.Lock()
		n.view++
		n.mu.Unlock()
	}

	return blockchain.Block{}, fmt.Errorf("falha ao atingir consenso PBFT após rotação de líder: %w", lastErr)
}

// proposeAsLeader executa as 3 fases do PBFT a partir do líder atual.
func (n *PBFTNode) proposeAsLeader(txs []blockchain.Transaction, view uint64) (blockchain.Block, error) {
	n.proposeMu.Lock()
	defer n.proposeMu.Unlock()

	ts := time.Now().Unix()
	if len(txs) > 0 && txs[0].TimestampUnix > ts {
		ts = txs[0].TimestampUnix
	}

	candidate, err := n.chain.BuildCandidateBlock(n.nodeID, view, ts, txs)
	if err != nil {
		return blockchain.Block{}, err
	}

	waitCh := n.registerWaiter(candidate.Hash)

	// O próprio líder processa o Propose (gera e difunde seu voto PREPARE)
	if err := n.HandlePropose(candidate); err != nil {
		return blockchain.Block{}, err
	}

	// Fase 1 (Propose): envia o bloco candidato para todos os peers em paralelo
	for _, peerURL := range n.peers {
		url := peerURL
		go func() {
			_ = n.client.SendPropose(url, candidate)
		}()
	}

	select {
	case committed := <-waitCh:
		return committed, nil
	case <-time.After(n.roundTimeout):
		return blockchain.Block{}, fmt.Errorf("timeout aguardando quórum PBFT (>= %d/4) para bloco %d",
			blockchain.QuorumSize, candidate.Height)
	}
}

func (n *PBFTNode) registerWaiter(blockHash string) chan blockchain.Block {
	ch := make(chan blockchain.Block, 1)
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.committedHash[blockHash] {
		tip := n.chain.Tip()
		if tip.Hash == blockHash {
			ch <- tip
			return ch
		}
	}
	n.waiters[blockHash] = append(n.waiters[blockHash], ch)
	return ch
}

// HandlePropose processa um bloco candidato recebido na Fase 1 do PBFT.
// Rejeita automaticamente blocos com PrevHash/Hash/Assinatura/Regras inválidos.
func (n *PBFTNode) HandlePropose(block blockchain.Block) error {
	// Rejeita blocos com integridade/assinaturas/regras inválidas
	if err := n.chain.ValidateCandidateBlock(block); err != nil {
		return fmt.Errorf("bloco candidato %d rejeitado: %w", block.Height, err)
	}

	var votesToBroadcast []blockchain.Vote

	n.mu.Lock()
	if n.committedHash[block.Hash] {
		n.mu.Unlock()
		return nil
	}

	n.pendingBlocks[block.Hash] = block

	if !n.sentPrepare[block.Hash] {
		prepVote, err := blockchain.NewSignedVote(n.wallet, blockchain.PhasePrepare, block.Height, block.View, block.Hash)
		if err != nil {
			n.mu.Unlock()
			return err
		}
		n.sentPrepare[block.Hash] = true
		n.recordVoteLocked(prepVote)
		votesToBroadcast = append(votesToBroadcast, prepVote)
	}

	// Caso votos PREPARE/COMMIT tenham chegado antes do PROPOSE, já avança de fase
	moreVotes, committedBlock := n.checkQuorumTransitionsLocked(block.Hash)
	votesToBroadcast = append(votesToBroadcast, moreVotes...)
	n.mu.Unlock()

	if committedBlock != nil {
		n.finalizeCommittedBlock(*committedBlock)
	}
	n.broadcastVotes(votesToBroadcast)
	return nil
}

// HandleVote processa um voto PREPARE ou COMMIT recebido de um validador.
func (n *PBFTNode) HandleVote(vote blockchain.Vote) error {
	valID, authorized := n.validators[vote.ValidatorPubKey]
	if !authorized || valID != vote.ValidatorID {
		return fmt.Errorf("voto rejeitado: validador não autorizado (%s)", vote.ValidatorID)
	}
	if err := vote.Verify(); err != nil {
		return fmt.Errorf("voto rejeitado: assinatura inválida (%w)", err)
	}

	var votesToBroadcast []blockchain.Vote
	var committedBlock *blockchain.Block

	n.mu.Lock()
	if n.committedHash[vote.BlockHash] {
		n.mu.Unlock()
		return nil
	}
	n.recordVoteLocked(vote)
	votesToBroadcast, committedBlock = n.checkQuorumTransitionsLocked(vote.BlockHash)
	n.mu.Unlock()

	if committedBlock != nil {
		n.finalizeCommittedBlock(*committedBlock)
	}
	n.broadcastVotes(votesToBroadcast)
	return nil
}

func (n *PBFTNode) recordVoteLocked(vote blockchain.Vote) {
	switch vote.Phase {
	case blockchain.PhasePrepare:
		if n.prepareVotes[vote.BlockHash] == nil {
			n.prepareVotes[vote.BlockHash] = make(map[string]blockchain.Vote)
		}
		n.prepareVotes[vote.BlockHash][vote.ValidatorPubKey] = vote
	case blockchain.PhaseCommit:
		if n.commitVotes[vote.BlockHash] == nil {
			n.commitVotes[vote.BlockHash] = make(map[string]blockchain.Vote)
		}
		n.commitVotes[vote.BlockHash][vote.ValidatorPubKey] = vote
	}
}

// checkQuorumTransitionsLocked verifica se o bloco atingiu quórum de PREPARE (>= 3) ou COMMIT (>= 3).
// Deve ser chamada com n.mu travado.
func (n *PBFTNode) checkQuorumTransitionsLocked(blockHash string) ([]blockchain.Vote, *blockchain.Block) {
	block, hasBlock := n.pendingBlocks[blockHash]
	if !hasBlock {
		return nil, nil
	}

	var outVotes []blockchain.Vote

	// Fase 2 -> Fase 3: atingiu >= 3 votos PREPARE distintos, emite COMMIT
	if !n.sentCommit[blockHash] && len(n.prepareVotes[blockHash]) >= blockchain.QuorumSize {
		commitVote, err := blockchain.NewSignedVote(n.wallet, blockchain.PhaseCommit, block.Height, block.View, block.Hash)
		if err == nil {
			n.sentCommit[blockHash] = true
			n.recordVoteLocked(commitVote)
			outVotes = append(outVotes, commitVote)
		}
	}

	// Fase 3 -> Finalização: atingiu >= 3 votos COMMIT distintos, prepara bloco certificado
	if !n.committedHash[blockHash] && len(n.commitVotes[blockHash]) >= blockchain.QuorumSize {
		votes := make([]blockchain.Vote, 0, len(n.commitVotes[blockHash]))
		for _, v := range n.commitVotes[blockHash] {
			votes = append(votes, v)
		}
		sort.Slice(votes, func(i, j int) bool {
			return votes[i].ValidatorID < votes[j].ValidatorID
		})
		block.CommitVotes = votes
		n.committedHash[blockHash] = true
		return outVotes, &block
	}

	return outVotes, nil
}

func (n *PBFTNode) finalizeCommittedBlock(block blockchain.Block) {
	if err := n.chain.AppendCommittedBlock(block); err != nil {
		// Se houve corrida ou divergência, limpa flag para permitir sync
		n.mu.Lock()
		delete(n.committedHash, block.Hash)
		n.mu.Unlock()
		return
	}

	n.mu.Lock()
	ws := n.waiters[block.Hash]
	delete(n.waiters, block.Hash)
	delete(n.pendingBlocks, block.Hash)
	n.mu.Unlock()

	for _, ch := range ws {
		select {
		case ch <- block:
		default:
		}
	}
}

func (n *PBFTNode) broadcastVotes(votes []blockchain.Vote) {
	for _, v := range votes {
		voteCopy := v
		for _, peerURL := range n.peers {
			url := peerURL
			go func() {
				_ = n.client.SendVote(url, voteCopy)
			}()
		}
	}
}

// RegisterHTTPHandlers registra os endpoints P2P do consenso PBFT no roteador HTTP interno do servidor.
func (n *PBFTNode) RegisterHTTPHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/p2p/tx", n.httpHandleTx)
	mux.HandleFunc("/p2p/propose", n.httpHandlePropose)
	mux.HandleFunc("/p2p/vote", n.httpHandleVote)
	mux.HandleFunc("/p2p/status", n.httpHandleStatus)
	mux.HandleFunc("/p2p/chain", n.httpHandleChain)
}

func (n *PBFTNode) httpHandleTx(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeP2PError(w, http.StatusMethodNotAllowed, "use POST")
		return
	}
	var tx blockchain.Transaction
	if err := decodeJSONBody(r, &tx); err != nil {
		writeP2PError(w, http.StatusBadRequest, err.Error())
		return
	}

	n.mu.Lock()
	view := n.view
	n.mu.Unlock()

	block, err := n.proposeAsLeader([]blockchain.Transaction{tx}, view)
	if err != nil {
		writeP2PError(w, http.StatusConflict, err.Error())
		return
	}
	writeP2PJSON(w, http.StatusOK, block)
}

func (n *PBFTNode) httpHandlePropose(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeP2PError(w, http.StatusMethodNotAllowed, "use POST")
		return
	}
	var block blockchain.Block
	if err := decodeJSONBody(r, &block); err != nil {
		writeP2PError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := n.HandlePropose(block); err != nil {
		writeP2PError(w, http.StatusConflict, err.Error())
		return
	}
	writeP2PJSON(w, http.StatusOK, map[string]string{"status": "PREPARED"})
}

func (n *PBFTNode) httpHandleVote(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeP2PError(w, http.StatusMethodNotAllowed, "use POST")
		return
	}
	var vote blockchain.Vote
	if err := decodeJSONBody(r, &vote); err != nil {
		writeP2PError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := n.HandleVote(vote); err != nil {
		writeP2PError(w, http.StatusConflict, err.Error())
		return
	}
	writeP2PJSON(w, http.StatusOK, map[string]string{"status": "ACCEPTED"})
}

func (n *PBFTNode) httpHandleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeP2PError(w, http.StatusMethodNotAllowed, "use GET")
		return
	}
	writeP2PJSON(w, http.StatusOK, n.Status())
}

func (n *PBFTNode) httpHandleChain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeP2PError(w, http.StatusMethodNotAllowed, "use GET")
		return
	}
	var fromHeight uint64
	if raw := r.URL.Query().Get("from"); raw != "" {
		parsed, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			writeP2PError(w, http.StatusBadRequest, "parâmetro 'from' inválido")
			return
		}
		fromHeight = parsed
	}
	writeP2PJSON(w, http.StatusOK, n.chain.BlocksFrom(fromHeight))
}

func decodeJSONBody(r *http.Request, dst any) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		return errors.New("falha ao ler corpo da requisição")
	}
	if err := json.Unmarshal(body, dst); err != nil {
		return fmt.Errorf("JSON inválido: %w", err)
	}
	return nil
}

func writeP2PJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeP2PError(w http.ResponseWriter, status int, msg string) {
	writeP2PJSON(w, status, map[string]string{"error": msg})
}
