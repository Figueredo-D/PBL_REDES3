# Especificação Arquitetural — Camada Blockchain e Consenso PBFT (VAIJUNTO)

> **Disciplina:** TEC502 — Problema 3 (VAIJUNTO com Blockchain)  
> **Linguagem:** Go 1.22 (`stdlib` apenas — zero dependências externas no `go.mod`)  
> **Modelo:** Blockchain Permissionada de Consórcio com PBFT Simplificado ($N = 4, f = 1$)

Este documento formaliza a arquitetura da camada de livro-razão distribuído (blockchain) acoplada ao consórcio VaiJunto, definindo:
1. Onde cada novo componente se acopla à estrutura atual sem quebrar a atomicidade das reservas (2PC).
2. As constantes e regras de negócio determinísticas do consórcio.
3. Os `structs` principais da blockchain e da máquina de estados.
4. O contrato dos endpoints P2P (`/p2p/*`).
5. O fluxo exato de detecção e recuperação automática contra adulteração de histórico.

---

## 1. Visão Geral e Topologia ($N = 4$ Nós Validadores)

Para satisfazer o modelo de consenso **PBFT simplificado** ($N = 3f + 1$ com $f = 1$), o consórcio passa de 3 para **4 empresas/nós validadores**, cada um em seu próprio contêiner Docker isolado (em máquinas distintas do laboratório):

| Nó Validador | Porta TCP (Clientes) | Porta HTTP Interna (`/internal/*` e `/p2p/*`) | Dados Locais |
|--------------|----------------------|-----------------------------------------------|--------------|
| `SERVER_A`   | `8080`               | `9080`                                        | `data/SERVER_A/` |
| `SERVER_B`   | `8081`               | `9081`                                        | `data/SERVER_B/` |
| `SERVER_C`   | `8082`               | `9082`                                        | `data/SERVER_C/` |
| `SERVER_D`   | `8083`               | `9083`                                        | `data/SERVER_D/` |

- **Quórum de Consenso:** $Q = 2f + 1 = 3$ de 4 nós ($\ge \frac{2}{3}$).
- **Tolerância a Falhas:** A rede continua finalizando blocos normalmente com 1 nó offline ou malicioso/adulterado.
- **Reuso de Porta Interna:** Os endpoints `/p2p/*` compartilham o mesmo servidor HTTP interno (`:9080..:9083`) já usado por `/internal/*`, mantendo o isolamento de rotas sem exigir portas adicionais no firewall do laboratório.
- **Zero Dependências Externas:** Toda a criptografia e comunicação utiliza exclusivamente a biblioteca padrão do Go (`crypto/ed25519`, `crypto/sha256`, `encoding/hex`, `encoding/json`, `net/http`, `sync`, `os`, `bufio`).

---

## 2. Acoplamento na Estrutura Atual do Repositório

### 2.1. Novos pacotes sob `internal/`

```text
internal/
├── crypto/
│   └── keys.go           # Geração, persistência, carregamento de chaves Ed25519, assinatura e verificação
├── blockchain/
│   ├── rules.go          # Constantes e regras determinísticas do consórcio
│   ├── types.go          # Structs: Transaction, Payloads, Block, Vote, LedgerState, EscrowRecord, ReputationEntry
│   ├── state.go          # Máquina de estados determinística (ApplyTransaction, ValidateTransaction, RebuildState)
│   └── chain.go          # Encadeamento SHA-256, bloco gênese, validação completa e persistência em blockchain.json
└── consensus/
    ├── pbft.go           # Motor PBFT em 3 fases (Propose, Prepare, Commit), coleta de quórum e view/líder
    ├── p2p_client.go     # Cliente HTTP para /p2p/propose, /p2p/vote, /p2p/chain, /p2p/status, /p2p/tx
    └── sync.go           # Anti-entropia periódica, detecção e recuperação automática contra adulteração
```

### 2.2. Pontos de acoplamento nos arquivos existentes (sem quebrar o 2PC)

| Arquivo Existente | Papel Atual (Problema 2) | Acoplamento para o Problema 3 |
|-------------------|--------------------------|-------------------------------|
| `cmd/server/main.go` | Sobe `SERVER_A..C`, configura `PEERS` e inicia HTTP/TCP/Recovery. | Adicionar defaults de `SERVER_D` (`:8083` / `:9083`), carregar/gerar par de chaves Ed25519 do validador, carregar registro de chaves públicas dos 4 validadores e inicializar o motor `consensus.PBFTNode`. |
| `internal/server/internal_http.go` | Expõe `/internal/rides`, `/internal/prepare`, `/internal/commit`, `/internal/abort`, `/internal/release`, `/internal/notify-cancel-ride`, `/internal/transactions/decision`. | Registrar as rotas `/p2p/propose`, `/p2p/vote`, `/p2p/chain`, `/p2p/status` e `/p2p/tx` no mesmo `http.ServeMux`. |
| `internal/server/listener.go` | Orquestra `handleBook` (2PC), `handleCancelBooking`, `handleCancelRide`, `handleSearch` e ações locais. | **Preservar o 2PC de assentos** e acoplar o ledger nos pontos críticos (ver seção 2.3), além de adicionar handlers para `MINT`, `BURN`, `BALANCE`, `COMPLETE_TRIP`, `NO_SHOW`, `REPUTATION` e `AUDIT_*`. |
| `internal/server/recovery.go` | Executa recovery do 2PC e devoluções pendentes a cada 5s. | Acoplar a chamada periódica de sincronização e verificação de integridade da blockchain (`SyncAndVerifyChain`). |
| `internal/protocol/messages.go` | Define `Request`, `Response` e payloads TCP. | Adicionar campos de assinatura na `Request` (`PublicKey`, `Nonce`, `TimestampUnix`, `Signature`) e novos tipos de ação/payload sem quebrar ações já existentes. |
| `cmd/driver-client/main.go` e `cmd/passenger-client/main.go` | Menus interativos TCP. | Gerenciar chaves Ed25519 do usuário e expor saldo/recarga/resgate, conclusão de viagem, cancelamento, *no-show*, avaliação/denúncia e auditoria. |
| `docker-compose.yml` | Sobe `server_a`, `server_b`, `server_c` e clientes. | Adicionar `server_d` e configurar os 4 peers + chaves públicas dos validadores. |

### 2.3. Integração Atômica: 2PC de Assentos + Escrow na Blockchain

Para manter **100% da atomicidade de reservas** sem deixar assento preso nem crédito bloqueado em caso de falha, o `handleBook` em `internal/server/listener.go` segue exatamente esta ordem:

1. **Validação Prévia (Leitura Local do Ledger):** Verifica se a assinatura do passageiro é válida e se `Balances[passenger] >= totalAmountCents`. Se não houver saldo suficiente, recusa imediatamente (sem sequer iniciar o 2PC).
2. **Fase 1 do 2PC (`PREPARE`):** Executa `PrepareWithPriority` (Lamport) localmente e em todos os peers envolvidos nos trechos. Se qualquer trecho falhar ou perder precedência, aborta o 2PC — nenhum crédito foi tocado.
3. **Consenso PBFT (`TX_RESERVE_ESCROW`):** Com todos os assentos garantidos em estado `PREPARED`, o servidor submete a transação `TX_RESERVE_ESCROW` assinada pelo passageiro ao PBFT.
   - Se o consenso falhar (ex.: tentativa de gasto duplo simultâneo, nonce inválido ou saldo insuficiente na hora do bloco), o coordenador **aborta o 2PC** e devolve todos os assentos preparados.
4. **Fase 2 do 2PC (`COMMIT`):** Somente após o bloco com `TX_RESERVE_ESCROW` atingir quórum ($\ge 3/4$) e ser finalizado na blockchain, o coordenador grava `DecisionCommit` no `txlog.json`, envia `COMMIT` aos peers e salva a reserva `CONFIRMED`.
   - Se algum peer cair durante o `COMMIT`, a thread `recovery.go` existente garante a efetivação do assento consultando `GET /internal/transactions/decision`.

---

## 3. Constantes e Regras de Negócio Determinísticas

Todas as validações da máquina de estados são **100% determinísticas**: nenhum nó pode usar `time.Now()` para decidir regras de negócio. Toda comparação temporal utiliza exclusivamente o `TimestampUnix` assinado dentro da transação.

> **Precisão Financeira (`int64` em centavos):** Todos os valores monetários no ledger são armazenados como `int64` em **centavos** (ex.: R\$ 35,50 = `3550`). Isso elimina erros de arredondamento de `float64` e garante conservação exata de valor ao centavo.

### Constantes do Consórcio (`internal/blockchain/rules.go`)

```go
const (
    // Consenso PBFT
    TotalValidators = 4
    MaxFaultyNodes  = 1
    QuorumSize      = 3 // 2f + 1

    // Política de Cancelamento
    FreeCancelWindowSeconds int64 = 2 * 3600 // 2 horas antes do embarque
    LateCancelRetentionPct  int64 = 30       // 30% retido para os motoristas
    LateCancelRefundPct     int64 = 70       // 70% devolvido ao passageiro

    // Política de Reputação
    MinRatingScore = 1
    MaxRatingScore = 5
)
```

### Regras Validadas por Todos os Nós

1. **Economia de Tokens (`Saldo Zero` + `TX_MINT` / `TX_BURN`):**
   - Toda conta nasce com saldo `0`.
   - **`TX_MINT`:** Deve ser assinada exclusivamente pela chave privada de um dos **4 nós validadores autorizados** (`Validators[tx.FromPubKey]`). Qualquer `TX_MINT` assinada por conta comum é rejeitada. Incrementa `Balances[target]` e `TotalMinted`.
   - **`TX_BURN`:** Assinada pelo próprio titular (motorista). Exige `Balances[from] >= amount` e `amount > 0`. Decrementa `Balances[from]` e incrementa `TotalBurned`.
   - **Invariante de Conservação de Valor** (verificável a qualquer momento por qualquer auditor):
     $$\sum \text{MINT} - \sum \text{BURN} = \sum_{u} \text{Balances}[u] + \sum_{e \in \text{LOCKED}} e.\text{TotalAmount}$$

2. **Proteção contra Gasto Duplo e Replay:**
   - Toda transação carrega `Nonce` estritamente sequencial por conta (`tx.Nonce == state.Nonces[tx.FromPubKey] + 1`) e assinatura Ed25519 válida sobre o hash canônico da transação.
   - O débito do saldo disponível para o escrow ocorre atomicamente na aplicação do bloco: duas transações concorrentes tentando gastar o mesmo saldo nunca podem ambas ser válidas.

3. **Escrow e Divisão Atômica (`TX_RESERVE_ESCROW` → `TX_COMPLETE_TRIP`):**
   - `TX_RESERVE_ESCROW` (assinada pelo passageiro): exige `Balances[passenger] >= TotalAmount`, onde `TotalAmount == sum(seg.Amount)`. Debita `TotalAmount` de `Balances[passenger]` e cria `EscrowRecord` em estado `LOCKED`.
   - `TX_COMPLETE_TRIP` (assinada pelo passageiro ou por validador autorizado mediante confirmação de embarque/conclusão): exige escrow em estado `LOCKED`. Em **uma única transição atômica**, marca o escrow como `COMPLETED` e credita `seg.Amount` em `Balances[seg.DriverPubKey]` para cada trecho.

4. **Política de Cancelamento (`TX_CANCEL_TRIP`):**
   - Exige escrow em estado `LOCKED` e assinatura do passageiro titular ou de um dos motoristas do itinerário.
   - **Se cancelado pelo passageiro:**
     - Se `escrow.DepartureUnix - tx.TimestampUnix >= 7200` ($\ge 2$ horas): devolve **100%** (`TotalAmount`) ao passageiro.
     - Se `escrow.DepartureUnix - tx.TimestampUnix < 7200` ($< 2$ horas — cancelamento tardio):
       - Para cada trecho `seg`: `driverShare := (seg.Amount * 30) / 100`, credita `driverShare` ao motorista do trecho e acumula `totalRetained += driverShare`.
       - Devolve `refund := escrow.TotalAmount - totalRetained` ao passageiro (preservando 100% dos centavos sem perda por divisão inteira).
       - Registra automaticamente uma `ReputationEntry` de categoria `LATE_CANCEL` vinculada à `PassengerPubKey`.
   - **Se cancelado pelo motorista:**
     - Devolve **100%** (`TotalAmount`) ao passageiro.
     - Registra automaticamente uma `ReputationEntry` de categoria `DRIVER_CANCEL` vinculada à `DriverPubKey` do motorista que cancelou.

5. **Política de *No-Show* (`TX_NO_SHOW`):**
   - Exige escrow em estado `LOCKED`.
   - **Ausência do passageiro (`NO_SHOW_PASSENGER`):** Assinada pelo motorista (ou validador da empresa do trecho). Repassa **100%** do valor de cada trecho ao respectivo motorista (ou do trecho reportado) e registra ocorrência `NO_SHOW_PASSENGER` no histórico permanente do passageiro.
   - **Ausência do motorista (`NO_SHOW_DRIVER`):** Assinada pelo passageiro (ou validador). Devolve **100%** ao passageiro e registra ocorrência grave `NO_SHOW_DRIVER` no histórico permanente do motorista.

6. **Reputação Imutável (*Append-Only*, `TX_REPUTATION`):**
   - Sempre vinculada à `TargetPubKey` (nunca ao `CompanyID`), garantindo portabilidade entre empresas.
   - Nenhuma transação pode editar ou remover entradas em `Reputations`.
   - Para `RATING` (avaliação com nota `1..5` + comentário) ou `COMPLAINT` (denúncia):
     - Exige que exista `EscrowRecord` para `BookingID` com status `COMPLETED` (ou `CANCELLED`/`NO_SHOW` para denúncias).
     - Exige que `tx.FromPubKey` tenha participado efetivamente daquele itinerário (se passageiro avaliando motorista, `tx.FromPubKey == escrow.PassengerPubKey` e `TargetPubKey` deve constar nos trechos do itinerário).
     - Impede avaliação duplicada para o mesmo `(BookingID, AuthorPubKey, TargetPubKey, Category)`.

---

## 4. Modelagem dos Structs Principais (`internal/blockchain/types.go`)

> **Regra de Determinismo na Serialização:** Structs que entram no cálculo de hash ou assinatura (`Transaction`, `BlockHeader`, `Vote`) **não utilizam `map`** (cuja ordem de serialização/iteração não é garantida), usando apenas campos escalares e slices ordenados.

### 4.1. Transação e Payloads

```go
type TxType string

const (
    TxMint          TxType = "MINT"
    TxBurn          TxType = "BURN"
    TxReserveEscrow TxType = "RESERVE_ESCROW"
    TxCompleteTrip  TxType = "COMPLETE_TRIP"
    TxCancelTrip    TxType = "CANCEL_TRIP"
    TxNoShow        TxType = "NO_SHOW"
    TxReputation    TxType = "REPUTATION"
)

type Transaction struct {
    ID            string          `json:"id"`             // SHA-256 hex do conteúdo canônico (sem Signature)
    Type          TxType          `json:"type"`           // Tipo da operação
    FromPubKey    string          `json:"from_pub_key"`   // Chave pública Ed25519 (hex) do autor da transação
    Nonce         uint64          `json:"nonce"`          // Contador monotônico da conta FromPubKey (anti-replay/double-spend)
    TimestampUnix int64           `json:"timestamp_unix"` // Timestamp Unix (segundos) assinado pelo autor
    Payload       json.RawMessage `json:"payload"`        // JSON canônico específico do TxType
    Signature     string          `json:"signature"`      // Assinatura Ed25519 (hex) sobre os campos acima
}
```

#### Payloads por Tipo de Transação

```go
type MintPayload struct {
    TargetPubKey string `json:"target_pub_key"` // Carteira que recebe os créditos
    AmountCents  int64  `json:"amount_cents"`   // Valor em centavos (> 0)
    CompanyID    string `json:"company_id"`     // Empresa emissora (ex: SERVER_A)
    ReferenceID  string `json:"reference_id"`   // Comprovante/ID do depósito bancário simulado
}

type BurnPayload struct {
    AmountCents int64  `json:"amount_cents"` // Valor em centavos (> 0)
    CompanyID   string `json:"company_id"`   // Empresa onde o motorista solicita o saque
}

type EscrowSegment struct {
    RideID       string `json:"ride_id"`
    CompanyID    string `json:"company_id"`
    DriverPubKey string `json:"driver_pub_key"`
    From         string `json:"from"`
    To           string `json:"to"`
    AmountCents  int64  `json:"amount_cents"`
}

type ReserveEscrowPayload struct {
    BookingID     string          `json:"booking_id"`
    DepartureUnix int64           `json:"departure_unix"` // Horário de partida do 1º trecho (base para regra das 2h)
    TotalCents    int64           `json:"total_cents"`    // Deve igualar a soma de Segments[].AmountCents
    Segments      []EscrowSegment `json:"segments"`
}

type CompleteTripPayload struct {
    BookingID string `json:"booking_id"`
}

type CancelTripPayload struct {
    BookingID string `json:"booking_id"`
    ActorRole string `json:"actor_role"` // "PASSENGER" ou "DRIVER"
    Reason    string `json:"reason,omitempty"`
}

type NoShowPayload struct {
    BookingID    string `json:"booking_id"`
    AbsentRole   string `json:"absent_role"`    // "PASSENGER" ou "DRIVER"
    AbsentPubKey string `json:"absent_pub_key"` // Chave pública de quem faltou ao embarque
    Reason       string `json:"reason,omitempty"`
}

type ReputationCategory string

const (
    RepRating          ReputationCategory = "RATING"
    RepComplaint       ReputationCategory = "COMPLAINT"
    RepLateCancel      ReputationCategory = "LATE_CANCEL"
    RepDriverCancel    ReputationCategory = "DRIVER_CANCEL"
    RepNoShowPassenger ReputationCategory = "NO_SHOW_PASSENGER"
    RepNoShowDriver    ReputationCategory = "NO_SHOW_DRIVER"
)

type ReputationPayload struct {
    BookingID    string             `json:"booking_id"`
    TargetPubKey string             `json:"target_pub_key"`
    Category     ReputationCategory `json:"category"` // "RATING" ou "COMPLAINT"
    Score        int                `json:"score"`    // 1..5 para RATING; 0 para COMPLAINT
    Comment      string             `json:"comment"`
}
```

### 4.2. Bloco e Votos PBFT

```go
type VotePhase string

const (
    PhasePrepare VotePhase = "PREPARE"
    PhaseCommit  VotePhase = "COMMIT"
)

type Vote struct {
    Phase           VotePhase `json:"phase"`             // "PREPARE" ou "COMMIT"
    Height          uint64    `json:"height"`            // Altura do bloco votado
    View            uint64    `json:"view"`              // Número da view (para troca de líder em caso de falha)
    BlockHash       string    `json:"block_hash"`        // Hash SHA-256 do bloco proposto
    ValidatorID     string    `json:"validator_id"`      // Ex: "SERVER_A"
    ValidatorPubKey string    `json:"validator_pub_key"` // Chave pública Ed25519 (hex) do validador
    Signature       string    `json:"signature"`         // Assinatura Ed25519 (hex) sobre (Phase, Height, View, BlockHash, ValidatorID)
}

type Block struct {
    Height        uint64        `json:"height"`         // 0 = Gênese, 1, 2, ...
    View          uint64        `json:"view"`           // View em que o bloco foi proposto
    TimestampUnix int64         `json:"timestamp_unix"` // Timestamp Unix do bloco
    PrevHash      string        `json:"prev_hash"`      // Hash SHA-256 do bloco anterior ("0000...0" no gênese)
    TxRootHash    string        `json:"tx_root_hash"`   // Hash SHA-256 determinístico da lista ordenada de Transactions
    ProposerID    string        `json:"proposer_id"`    // ID do líder que propôs o bloco
    Transactions  []Transaction `json:"transactions"`   // Transações incluídas neste bloco
    Hash          string        `json:"hash"`           // SHA-256 hex do cabeçalho (Height, View, TimestampUnix, PrevHash, TxRootHash, ProposerID)
    CommitVotes   []Vote        `json:"commit_votes"`   // Certificado de quórum (>= 3 votos COMMIT válidos e distintos)
}
```

### 4.3. Estado do Ledger, Escrow e Reputação

```go
type EscrowStatus string

const (
    EscrowLocked    EscrowStatus = "LOCKED"
    EscrowCompleted EscrowStatus = "COMPLETED"
    EscrowCancelled EscrowStatus = "CANCELLED"
    EscrowNoShow    EscrowStatus = "NO_SHOW"
)

type EscrowRecord struct {
    BookingID       string          `json:"booking_id"`
    PassengerPubKey string          `json:"passenger_pub_key"`
    DepartureUnix   int64           `json:"departure_unix"`
    TotalCents      int64           `json:"total_cents"`
    Segments        []EscrowSegment `json:"segments"`
    Status          EscrowStatus    `json:"status"`
    CreatedAtUnix   int64           `json:"created_at_unix"`
    ResolvedAtUnix  int64           `json:"resolved_at_unix,omitempty"`
    ResolutionNote  string          `json:"resolution_note,omitempty"`
}

type ReputationEntry struct {
    ID            string             `json:"id"`             // Hash único (txID + índice)
    TargetPubKey  string             `json:"target_pub_key"` // Usuário avaliado/penalizado (portável entre empresas)
    AuthorPubKey  string             `json:"author_pub_key"` // Quem originou o registro (ou chave do sistema/autor da tx)
    BookingID     string             `json:"booking_id"`
    Category      ReputationCategory `json:"category"`
    Score         int                `json:"score,omitempty"` // 1..5 se RATING
    Comment       string             `json:"comment,omitempty"`
    TimestampUnix int64              `json:"timestamp_unix"`
    BlockHeight   uint64             `json:"block_height"`
}

type LedgerState struct {
    Balances        map[string]int64             `json:"balances"`          // pubKey -> saldo livre em centavos
    Nonces          map[string]uint64            `json:"nonces"`            // pubKey -> último nonce confirmado
    Escrows         map[string]*EscrowRecord     `json:"escrows"`           // bookingID -> registro de escrow
    Reputations     map[string][]ReputationEntry `json:"reputations"`       // targetPubKey -> lista append-only
    SubmittedReps   map[string]bool              `json:"submitted_reps"`    // chave "bookingID|author|target|category" -> anti-duplicação
    Validators      map[string]string            `json:"validators"`        // pubKey -> validatorID (ex: pubKey -> "SERVER_A")
    TotalMinted     int64                        `json:"total_minted"`      // Soma histórica de todos os MINTs
    TotalBurned     int64                        `json:"total_burned"`      // Soma histórica de todos os BURNs
}
```

---

## 5. Contrato dos Endpoints P2P (`/p2p/*`)

Todos os endpoints P2P trafegam JSON sobre HTTP/1.1 na porta interna do nó (`:9080..:9083`), com timeout curto (ex.: `3s`) para não bloquear o consenso quando um nó estiver offline.

| Método e Rota | Quem Chama | Payload / Query | Função no Consenso PBFT |
|---------------|------------|-----------------|-------------------------|
| `POST /p2p/tx` | Nó seguidor → Líder atual | `Transaction` | Encaminha uma transação assinada (recebida de um cliente) ao líder da view atual para iniciar uma rodada de proposta. |
| `POST /p2p/propose` | Líder → Todos os Peers | `Block` (sem `CommitVotes`) | **Fase 1 (Propose):** Envia o bloco candidato. Cada peer valida `Height`, `PrevHash`, assinaturas das transações e executa a simulação determinística no `LedgerState`. Se válido, emite e faz broadcast de seu `Vote{Phase: PREPARE}`. |
| `POST /p2p/vote` | Validador → Todos os Peers | `Vote` (`PREPARE` ou `COMMIT`) | **Fases 2 e 3 (Prepare / Commit):** Verifica a assinatura do validador. Ao acumular $\ge 3$ votos `PREPARE` distintos para o mesmo `(Height, BlockHash)`, o nó envia seu `Vote{Phase: COMMIT}`. Ao acumular $\ge 3$ votos `COMMIT` distintos, o nó anexa `CommitVotes` ao bloco, aplica ao `LedgerState` e persiste atomicamente em `blockchain.json`. |
| `GET /p2p/status` | Qualquer Nó (Sync / Auditoria) | — | Retorna `{ "validator_id", "height", "tip_hash", "view" }` para comparação rápida de divergência entre os nós. |
| `GET /p2p/chain` | Nó Divergente / Auditor | `?from=<height>` (opcional, padrão `0`) | Retorna a lista ordenada de blocos `[]Block` (cada um com seus `CommitVotes`) para validação completa e ressincronização. |

### Eleição Determinística de Líder e Tolerância a Líder Offline
- O líder da rodada é escolhido deterministicamente por:
  `leaderIndex = (height + view) % 4` sobre a lista ordenada `["SERVER_A", "SERVER_B", "SERVER_C", "SERVER_D"]`.
- Se o líder atual estiver offline (timeout ao enviar `/p2p/tx` ou ausência de proposta após timeout), o nó incrementa `view` e redireciona a proposta ao próximo líder, garantindo **liveness** com até $f = 1$ nó parado.

---

## 6. Fluxo de Recuperação Automática Contra Adulteração

Durante a arguição, um nó pode ter seu arquivo `data/SERVER_X/blockchain.json` editado manualmente (ex.: alterar um saldo, remover uma avaliação negativa ou modificar um bloco antigo). O sistema trata isso automaticamente em **3 linhas de defesa**, sem intervenção manual:

```text
  [Nó X adultera blockchain.json]
                │
                ▼
  1. Validação Local (Startup / Leitura)
     - Recalcula hash de cada bloco e PrevHash
     - Verifica assinatura de cada transação
     - Verifica >= 3 CommitVotes válidos de validadores autorizados por bloco
     - Se falhar -> marca cadeia local como CORROMPIDA e dispara Sync imediato
                │
                ▼ (Mesmo se Nó X forçar envio de bloco adulterado)
  2. Rejeição Automática pela Supermaioria (3/4 nós honestos)
     - Peers recebem /p2p/propose ou /p2p/vote do Nó X
     - PrevHash diverge OU faltam 3 assinaturas de validadores no histórico
     - Peers rejeitam (HTTP 409) e continuam operando normalmente com quórum 3/4
                │
                ▼
  3. Auto-Cura / Ressincronização (Anti-Entropia a cada 5s ou após rejeição)
     - Nó X consulta GET /p2p/status nos demais peers
     - Identifica supermaioria concordando em (Height, TipHash) diferente
     - Baixa cadeia completa via GET /p2p/chain?from=0 de um peer da maioria
     - Valida criptograficamente TODOS os blocos desde o Gênese (hashes + >= 3 CommitVotes)
     - Substitui blockchain.json atomicamente (arquivo .tmp + os.Rename)
     - Reconstrói LedgerState em memória por replay determinístico desde o Bloco 0
```

### Por que o atacante não consegue impor o histórico adulterado?
1. **Encadeamento SHA-256:** Editar qualquer transação ou avaliação antiga altera o `TxRootHash` e o `Hash` daquele bloco, quebrando o `PrevHash` de todos os blocos subsequentes.
2. **Assinaturas Ed25519 de Quórum (`CommitVotes`):** Mesmo que o atacante recalcule todos os hashes locais após adulterar o JSON, ele **não possui as chaves privadas dos outros 2 validadores** para forjar os 3 votos `COMMIT` exigidos em cada bloco.
3. **Replay Determinístico:** O `LedgerState` nunca é confiado cegamente em disco — ele é sempre reconstruído e validado a partir dos blocos certificados com quórum.
