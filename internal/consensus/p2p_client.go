package consensus

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Figueredo-D/PBL_REDES/internal/blockchain"
)

// P2PClient encapsula as chamadas HTTP JSON entre nós validadores sob o prefixo /p2p/.
type P2PClient struct {
	httpClient *http.Client
}

// NewP2PClient cria um cliente P2P com timeout curto para manter liveness quando um nó cai.
func NewP2PClient(timeout time.Duration) *P2PClient {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return &P2PClient{
		httpClient: &http.Client{Timeout: timeout},
	}
}

func normalizeBase(baseURL string) string {
	return strings.TrimRight(strings.TrimSpace(baseURL), "/")
}

// ForwardTx encaminha uma transação assinada de um nó seguidor ao líder via POST /p2p/tx.
func (c *P2PClient) ForwardTx(peerBaseURL string, tx blockchain.Transaction) (blockchain.Block, error) {
	var block blockchain.Block
	if err := c.postJSON(normalizeBase(peerBaseURL)+"/p2p/tx", tx, &block); err != nil {
		return blockchain.Block{}, err
	}
	return block, nil
}

// SendPropose envia um bloco candidato (Fase 1 PBFT) via POST /p2p/propose.
func (c *P2PClient) SendPropose(peerBaseURL string, block blockchain.Block) error {
	return c.postJSON(normalizeBase(peerBaseURL)+"/p2p/propose", block, nil)
}

// SendVote envia um voto assinado PREPARE ou COMMIT (Fases 2 e 3 PBFT) via POST /p2p/vote.
func (c *P2PClient) SendVote(peerBaseURL string, vote blockchain.Vote) error {
	return c.postJSON(normalizeBase(peerBaseURL)+"/p2p/vote", vote, nil)
}

// GetStatus consulta altura e hash do topo de um peer via GET /p2p/status.
func (c *P2PClient) GetStatus(peerBaseURL string) (blockchain.ChainStatus, error) {
	var status blockchain.ChainStatus
	url := normalizeBase(peerBaseURL) + "/p2p/status"

	resp, err := c.httpClient.Get(url)
	if err != nil {
		return status, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return status, err
	}
	if resp.StatusCode != http.StatusOK {
		return status, fmt.Errorf("status HTTP %d em %s: %s", resp.StatusCode, url, strings.TrimSpace(string(body)))
	}
	if err := json.Unmarshal(body, &status); err != nil {
		return status, err
	}
	return status, nil
}

// GetChain baixa os blocos de um peer a partir de fromHeight via GET /p2p/chain?from=H.
func (c *P2PClient) GetChain(peerBaseURL string, fromHeight uint64) ([]blockchain.Block, error) {
	url := fmt.Sprintf("%s/p2p/chain?from=%d", normalizeBase(peerBaseURL), fromHeight)

	resp, err := c.httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status HTTP %d em %s: %s", resp.StatusCode, url, strings.TrimSpace(string(body)))
	}

	var blocks []blockchain.Block
	if err := json.Unmarshal(body, &blocks); err != nil {
		return nil, err
	}
	return blocks, nil
}

func (c *P2PClient) postJSON(url string, reqBody any, respOut any) error {
	raw, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	resp, err := c.httpClient.Post(url, "application/json", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("status HTTP %d em %s: %s", resp.StatusCode, url, strings.TrimSpace(string(body)))
	}
	if respOut != nil && len(body) > 0 {
		if err := json.Unmarshal(body, respOut); err != nil {
			return err
		}
	}
	return nil
}
