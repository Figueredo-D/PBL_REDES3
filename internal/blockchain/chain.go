package blockchain

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

var (
	ErrChainCorrupted    = errors.New("histórico local da blockchain corrompido ou adulterado")
	ErrInsufficientVotes = errors.New("quórum PBFT insuficiente de votos COMMIT válidos")
)

// Blockchain gerencia a cadeia imutável de blocos, o estado derivado (LedgerState)
// e a persistência atômica em disco (blockchain.json).
type Blockchain struct {
	mu         sync.RWMutex
	blocks     []Block
	state      *LedgerState
	validators map[string]string // pubKeyHex -> validatorID
	dataPath   string
	corrupted  bool
}

// NewGenesisBlock cria o bloco gênese determinístico (Height 0) idêntico em todos os nós.
func NewGenesisBlock() Block {
	txRoot, _ := ComputeTxRootHash([]Transaction{})
	b := Block{
		Height:        0,
		View:          0,
		TimestampUnix: GenesisTimestampUnix,
		PrevHash:      GenesisPrevHash,
		TxRootHash:    txRoot,
		ProposerID:    "GENESIS",
		Transactions:  []Transaction{},
		CommitVotes:   []Vote{},
	}
	b.Hash, _ = b.ComputeHash()
	return b
}

// LoadOrCreateBlockchain carrega a blockchain de dataPath ou inicializa com o bloco gênese.
// Se o arquivo em disco tiver sido adulterado, retorna a instância marcada como corrupted=true
// e ErrChainCorrupted para que o consenso acione a auto-cura automática junto à supermaioria.
func LoadOrCreateBlockchain(dataPath string, validators map[string]string) (*Blockchain, error) {
	bc := &Blockchain{
		validators: copyMap(validators),
		dataPath:   dataPath,
		state:      NewLedgerState(validators),
	}

	raw, err := os.ReadFile(dataPath)
	if os.IsNotExist(err) {
		genesis := NewGenesisBlock()
		bc.blocks = []Block{genesis}
		if err := bc.saveLocked(); err != nil {
			return nil, err
		}
		return bc, nil
	}
	if err != nil {
		return nil, fmt.Errorf("falha ao ler %s: %w", dataPath, err)
	}

	var loaded []Block
	if err := json.Unmarshal(raw, &loaded); err != nil {
		bc.blocks = []Block{NewGenesisBlock()}
		bc.corrupted = true
		return bc, fmt.Errorf("%w: JSON inválido (%v)", ErrChainCorrupted, err)
	}

	state, err := ValidateFullChain(loaded, bc.validators)
	if err != nil {
		bc.blocks = []Block{NewGenesisBlock()}
		bc.corrupted = true
		return bc, fmt.Errorf("%w: %v", ErrChainCorrupted, err)
	}

	bc.blocks = loaded
	bc.state = state
	return bc, nil
}

// ValidateFullChain valida integralmente uma cadeia desde o bloco gênese (Height 0):
// encadeamento PrevHash, Hash, TxRootHash, assinaturas das transações, quórum >= 3 de CommitVotes
// e replay determinístico do LedgerState.
func ValidateFullChain(blocks []Block, validators map[string]string) (*LedgerState, error) {
	if len(blocks) == 0 {
		return nil, errors.New("cadeia vazia")
	}

	expectedGenesis := NewGenesisBlock()
	if blocks[0].Height != 0 || blocks[0].Hash != expectedGenesis.Hash || blocks[0].PrevHash != GenesisPrevHash {
		return nil, errors.New("bloco gênese inválido ou adulterado")
	}

	state := NewLedgerState(validators)
	for i := 1; i < len(blocks); i++ {
		prev := blocks[i-1]
		curr := blocks[i]
		if err := validateBlockAgainst(curr, prev, state, validators, true); err != nil {
			return nil, fmt.Errorf("bloco %d inválido: %w", curr.Height, err)
		}
	}

	if err := state.VerifyConservation(); err != nil {
		return nil, err
	}
	return state, nil
}

func validateBlockAgainst(block Block, prev Block, state *LedgerState, validators map[string]string, requireCommitQuorum bool) error {
	if block.Height != prev.Height+1 {
		return fmt.Errorf("altura inválida: esperado %d, recebido %d", prev.Height+1, block.Height)
	}
	if block.PrevHash != prev.Hash {
		return fmt.Errorf("prev_hash divergente: esperado %s, recebido %s", prev.Hash, block.PrevHash)
	}
	if block.TimestampUnix <= 0 {
		return errors.New("timestamp_unix do bloco deve ser positivo")
	}

	expectedTxRoot, err := ComputeTxRootHash(block.Transactions)
	if err != nil {
		return err
	}
	if block.TxRootHash != expectedTxRoot {
		return fmt.Errorf("tx_root_hash inválido: esperado %s, recebido %s", expectedTxRoot, block.TxRootHash)
	}

	expectedHash, err := block.ComputeHash()
	if err != nil {
		return err
	}
	if block.Hash != expectedHash {
		return fmt.Errorf("hash do bloco inválido: esperado %s, recebido %s", expectedHash, block.Hash)
	}

	if requireCommitQuorum {
		if err := VerifyCommitQuorum(block, validators); err != nil {
			return err
		}
	}

	for _, tx := range block.Transactions {
		if err := state.ValidateAndApplyTx(tx, block.Height); err != nil {
			return fmt.Errorf("transação %s rejeitada: %w", tx.ID, err)
		}
	}
	return nil
}

// VerifyCommitQuorum comprova que o bloco possui >= QuorumSize (3) votos COMMIT válidos e distintos
// assinados por empresas validadoras autorizadas.
func VerifyCommitQuorum(block Block, validators map[string]string) error {
	seen := make(map[string]bool)
	validCount := 0

	for _, vote := range block.CommitVotes {
		if vote.Phase != PhaseCommit {
			continue
		}
		if vote.Height != block.Height || vote.BlockHash != block.Hash {
			continue
		}
		valID, authorized := validators[vote.ValidatorPubKey]
		if !authorized || valID != vote.ValidatorID {
			continue
		}
		if seen[vote.ValidatorPubKey] {
			continue
		}
		if err := vote.Verify(); err != nil {
			continue
		}
		seen[vote.ValidatorPubKey] = true
		validCount++
	}

	if validCount < QuorumSize {
		return fmt.Errorf("%w: válidos=%d, mínimo=%d", ErrInsufficientVotes, validCount, QuorumSize)
	}
	return nil
}

// BuildCandidateBlock monta um bloco candidato a partir do topo atual (sem CommitVotes ainda).
func (bc *Blockchain) BuildCandidateBlock(proposerID string, view uint64, timestampUnix int64, txs []Transaction) (Block, error) {
	bc.mu.RLock()
	defer bc.mu.RUnlock()

	prev := bc.blocks[len(bc.blocks)-1]
	txRoot, err := ComputeTxRootHash(txs)
	if err != nil {
		return Block{}, err
	}

	block := Block{
		Height:        prev.Height + 1,
		View:          view,
		TimestampUnix: timestampUnix,
		PrevHash:      prev.Hash,
		TxRootHash:    txRoot,
		ProposerID:    proposerID,
		Transactions:  txs,
		CommitVotes:   []Vote{},
	}
	block.Hash, err = block.ComputeHash()
	if err != nil {
		return Block{}, err
	}

	// Simula no clone antes de propor
	simState := bc.state.Clone()
	if err := validateBlockAgainst(block, prev, simState, bc.validators, false); err != nil {
		return Block{}, err
	}
	return block, nil
}

// ValidateCandidateBlock valida um bloco proposto por um peer contra o estado atual (sem exigir CommitVotes).
func (bc *Blockchain) ValidateCandidateBlock(block Block) error {
	bc.mu.RLock()
	defer bc.mu.RUnlock()

	if bc.corrupted {
		return ErrChainCorrupted
	}
	prev := bc.blocks[len(bc.blocks)-1]
	simState := bc.state.Clone()
	return validateBlockAgainst(block, prev, simState, bc.validators, false)
}

// AppendCommittedBlock valida o bloco com quórum >= 3 de CommitVotes, aplica ao estado e persiste em disco.
func (bc *Blockchain) AppendCommittedBlock(block Block) error {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	prev := bc.blocks[len(bc.blocks)-1]
	if block.Height == prev.Height && block.Hash == prev.Hash {
		return nil // idempotente
	}

	simState := bc.state.Clone()
	if err := validateBlockAgainst(block, prev, simState, bc.validators, true); err != nil {
		return err
	}

	bc.blocks = append(bc.blocks, block)
	bc.state = simState
	bc.corrupted = false
	return bc.saveLocked()
}

// ReplaceChain substitui a cadeia local por uma cadeia canônica validada criptograficamente da supermaioria.
// Utilizada na ressincronização pós-queda e na auto-cura contra adulteração local.
func (bc *Blockchain) ReplaceChain(newBlocks []Block) error {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	newState, err := ValidateFullChain(newBlocks, bc.validators)
	if err != nil {
		return fmt.Errorf("cadeia candidata rejeitada na validação completa: %w", err)
	}

	cp := make([]Block, len(newBlocks))
	copy(cp, newBlocks)

	bc.blocks = cp
	bc.state = newState
	bc.corrupted = false
	return bc.saveLocked()
}

// VerifyLocalIntegrity re-lê blockchain.json do disco e confirma se não houve adulteração manual.
func (bc *Blockchain) VerifyLocalIntegrity() error {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	if bc.dataPath == "" {
		return nil
	}
	raw, err := os.ReadFile(bc.dataPath)
	if err != nil {
		bc.corrupted = true
		return fmt.Errorf("%w: falha ao ler arquivo (%v)", ErrChainCorrupted, err)
	}

	var diskBlocks []Block
	if err := json.Unmarshal(raw, &diskBlocks); err != nil {
		bc.corrupted = true
		return fmt.Errorf("%w: JSON adulterado (%v)", ErrChainCorrupted, err)
	}

	if _, err := ValidateFullChain(diskBlocks, bc.validators); err != nil {
		bc.corrupted = true
		return fmt.Errorf("%w: %v", ErrChainCorrupted, err)
	}

	// Também detecta se o arquivo em disco divergiu do topo em memória
	if len(diskBlocks) != len(bc.blocks) || diskBlocks[len(diskBlocks)-1].Hash != bc.blocks[len(bc.blocks)-1].Hash {
		bc.corrupted = true
		return fmt.Errorf("%w: arquivo em disco divergiu do estado em memória", ErrChainCorrupted)
	}
	return nil
}

// Tip retorna o último bloco confirmado da cadeia.
func (bc *Blockchain) Tip() Block {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	return bc.blocks[len(bc.blocks)-1]
}

// Height retorna a altura do último bloco confirmado.
func (bc *Blockchain) Height() uint64 {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	return bc.blocks[len(bc.blocks)-1].Height
}

// IsCorrupted informa se a cadeia local foi sinalizada como corrompida/adulterada.
func (bc *Blockchain) IsCorrupted() bool {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	return bc.corrupted
}

// BlocksFrom retorna cópia dos blocos a partir da altura fromHeight.
func (bc *Blockchain) BlocksFrom(fromHeight uint64) []Block {
	bc.mu.RLock()
	defer bc.mu.RUnlock()

	if int(fromHeight) >= len(bc.blocks) {
		return []Block{}
	}
	out := make([]Block, len(bc.blocks)-int(fromHeight))
	copy(out, bc.blocks[fromHeight:])
	return out
}

// StateSnapshot retorna uma cópia segura do LedgerState atual para consultas e auditoria.
func (bc *Blockchain) StateSnapshot() *LedgerState {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	return bc.state.Clone()
}

// BalanceOf retorna o saldo livre atual em centavos de uma conta.
func (bc *Blockchain) BalanceOf(pubKeyHex string) int64 {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	return bc.state.Balances[pubKeyHex]
}

// NonceOf retorna o último nonce confirmado de uma conta.
func (bc *Blockchain) NonceOf(pubKeyHex string) uint64 {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	return bc.state.Nonces[pubKeyHex]
}

// ValidateTransaction valida uma transação em um clone do estado atual (pré-validação antes do consenso).
func (bc *Blockchain) ValidateTransaction(tx Transaction) error {
	bc.mu.RLock()
	defer bc.mu.RUnlock()

	if bc.corrupted {
		return ErrChainCorrupted
	}
	sim := bc.state.Clone()
	return sim.ValidateAndApplyTx(tx, bc.blocks[len(bc.blocks)-1].Height+1)
}

func (bc *Blockchain) saveLocked() error {
	if bc.dataPath == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(bc.dataPath), 0o755); err != nil {
		return fmt.Errorf("falha ao criar diretório da blockchain: %w", err)
	}
	data, err := json.MarshalIndent(bc.blocks, "", "  ")
	if err != nil {
		return fmt.Errorf("falha ao serializar blockchain: %w", err)
	}
	tmp := bc.dataPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("falha ao gravar arquivo temporário da blockchain: %w", err)
	}
	if err := os.Rename(tmp, bc.dataPath); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("falha ao persistir blockchain.json: %w", err)
	}
	return nil
}

func copyMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
