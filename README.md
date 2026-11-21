# VaiJunto com Blockchain — Consórcio Descentralizado de Caronas

> **Disciplina:** TEC502 — Problema 3 (VAIJUNTO com Blockchain)  
> **Linguagem:** Go 1.22 (`stdlib` exclusivamente — zero dependências externas no `go.mod`)  
> **Consenso:** PBFT Simplificado ($N = 4$ validadores, $f = 1$, quórum $\ge 3/4$) + Two-Phase Commit (2PC) com Precedência de Lamport

Sistema distribuído de caronas compartilhadas entre **quatro empresas independentes** (`SERVER_A`, `SERVER_B`, `SERVER_C` e `SERVER_D`), onde o registro financeiro (tokens, escrow, pagamentos atômicos, cancelamentos) e a reputação dos usuários são mantidos em uma **blockchain permissionada de consórcio**, transparente, auditável e resistente a adulteração — sem servidor central nem banco de dados compartilhado.

---

## Sumário

1. [Arquitetura do Consórcio](#1-arquitetura-do-consórcio)
2. [Conceitos e Garantias de Segurança](#2-conceitos-e-garantias-de-segurança)
3. [Regras de Negócio Determinísticas](#3-regras-de-negócio-determinísticas)
4. [Pré-requisitos](#4-pré-requisitos)
5. [Execução Local (Go direto)](#5-execução-local-go-direto)
6. [Execução com Docker Compose (4 contêineres isolados)](#6-execução-com-docker-compose-4-contêineres-isolados)
7. [Execução em 4 Máquinas Distintas do Laboratório](#7-execução-em-4-máquinas-distintas-do-laboratório)
8. [Usando os Clientes Interativos e o Auditor](#8-usando-os-clientes-interativos-e-o-auditor)
9. [Scripts de Teste e Demonstração da Arguição](#9-scripts-de-teste-e-demonstração-da-arguição)
10. [Estrutura do Projeto](#10-estrutura-do-projeto)

---

## 1. Arquitetura do Consórcio

```text
                      CONSÓRCIO VAIJUNTO (PBFT N=4, Quórum 3/4)
  ┌────────────────────────────────────────────────────────────────────────┐
  │  [Motorista / Passageiro] ──TCP (Ed25519)──► [SERVER_A :8080 | :9080] │
  │  [Motorista / Passageiro] ──TCP (Ed25519)──► [SERVER_B :8081 | :9081] │
  │  [Motorista / Passageiro] ──TCP (Ed25519)──► [SERVER_C :8082 | :9082] │
  │  [Motorista / Passageiro] ──TCP (Ed25519)──► [SERVER_D :8083 | :9083] │
  │                                                                        │
  │  Comunicação Inter-Nós (HTTP interno :9080..:9083):                    │
  │   • /internal/*  → Busca BFS, 2PC (Prepare/Commit/Abort) e Recovery    │
  │   • /p2p/*       → Consenso PBFT (tx, propose, vote, status, chain)    │
  └────────────────────────────────────────────────────────────────────────┘
```

| Nó Validador | Porta TCP (Clientes) | Porta HTTP Interna (`/internal/*` e `/p2p/*`) | Persistência Local |
|--------------|----------------------|-----------------------------------------------|--------------------|
| `SERVER_A`   | `8080`               | `9080`                                        | `data/SERVER_A/`   |
| `SERVER_B`   | `8081`               | `9081`                                        | `data/SERVER_B/`   |
| `SERVER_C`   | `8082`               | `9082`                                        | `data/SERVER_C/`   |
| `SERVER_D`   | `8083`               | `9083`                                        | `data/SERVER_D/`   |

---

## 2. Conceitos e Garantias de Segurança

Esta seção explicita os fundamentos técnicos que sustentam a segurança e a auditabilidade do sistema (substituindo o relatório técnico):

### 2.1. Identidade Criptográfica e Não-Repúdio (`crypto/ed25519`)
* Cada usuário (passageiro ou motorista) e cada empresa validadora possui um par de chaves assimétricas **Ed25519** (`internal/crypto/keys.go`).
* A chave pública (`PublicKey` em hex) é a identidade global do usuário no consórcio, **independente da empresa** em que ele se conectou.
* Toda operação que altera saldo, reserva/escrow ou reputação exige assinatura digital Ed25519 sobre a **serialização JSON canônica** (`CanonicalSerialize`, com chaves ordenadas recursivamente), cobrindo `action`, `data`, `sender_pub_key`, `nonce` e `timestamp`.
* O interceptor `RequestValidator` (`internal/server/auth.go`) valida todas as assinaturas na entrada do servidor, bloqueando imediatamente requisições sem assinatura (`MISSING_SIGNATURE`), adulteradas por um único byte (`INVALID_SIGNATURE`), tentativas de operar em nome de terceiros (`IMPERSONATION_DETECTED`) e ataques de repetição (`REPLAY_ATTACK`).

### 2.2. Impossibilidade de Gasto Duplo e Conservação Exata de Valor
* Todas as contas nascem com **saldo `0`** e todos os valores são representados em **centavos (`int64`)** para eliminar erros de ponto flutuante (`float64`).
* A emissão de créditos (`TX_MINT`) só é aceita quando assinada pela chave privada de um dos **4 nós validadores autorizados**; o resgate (`TX_BURN`) exige assinatura e saldo do titular.
* Cada conta possui um **`Nonce` estritamente sequencial** validado on-chain (`tx.Nonce == state.Nonces[from] + 1`). Mesmo que um passageiro dispare duas reservas simultâneas em empresas diferentes, apenas uma transação com o próximo nonce válido (e saldo suficiente) pode ser incluída no bloco pelo consenso PBFT.
* A cada transação aplicada, a máquina de estados verifica a invariante matemática de conservação de valor:
  $$\sum \text{MINT} - \sum \text{BURN} = \sum_{u} \text{Balances}[u] + \sum_{e \in \text{LOCKED}} e.\text{TotalCents}$$

### 2.3. Atomicidade Integrada: 2PC de Assentos + Escrow na Blockchain
Para manter a reserva de assentos atômica sem travar créditos nem vender assentos duas vezes, `handleBook` (`internal/server/listener.go`) executa:
1. **Pré-validação no Ledger:** verifica assinatura, nonce e saldo livre antes de tocar qualquer assento.
2. **Fase 1 do 2PC (`PREPARE` com Precedência de Lamport):** trava os assentos em todas as empresas do itinerário. Se qualquer trecho falhar, aborta o 2PC sem debitar créditos.
3. **Consenso PBFT (`TX_RESERVE_ESCROW`):** submete o bloqueio de créditos à rede. Se falhar (ex.: gasto duplo simultâneo), o coordenador aborta o 2PC e devolve todos os assentos preparados.
4. **Fase 2 do 2PC (`COMMIT`):** somente após o bloco do escrow atingir quórum ($\ge 3/4$), grava `DecisionCommit` em `txlog.json` e efetiva os assentos (com recuperação automática via `recovery.go`).

### 2.4. Por que $N = 4$ Validadores no PBFT? (Tolerância a Falhas e Adulteração)
Pelo teorema de consenso tolerante a falhas bizantinas (Lamport–Shostak–Pease), para tolerar $f$ nós que podem cair **ou** agir de forma maliciosa/adulterada, a rede exige:
$$N \ge 3f + 1 \implies \text{para } f = 1,\; N = 4 \text{ nós e quórum } Q = 2f + 1 = 3 \text{ votos } (\ge \tfrac{2}{3})$$
* **Queda de 1 nó:** os 3 nós restantes ainda formam quórum (`3/4`) e continuam finalizando blocos normalmente (com rotação automática de líder `leader = (height + view) % 4`). Quando o nó retorna, sincroniza automaticamente.
* **Adulteração manual de `blockchain.json`:** cada bloco encadeia o `PrevHash` SHA-256 do bloco anterior, o `TxRootHash` das transações e um certificado com **$\ge 3$ votos `COMMIT` assinados** por validadores distintos (`CommitVotes`).
  1. Se um nó editar seu arquivo local (ex.: aumentar saldo ou apagar avaliação negativa), o hash do bloco quebra.
  2. Mesmo que o atacante recalcule todos os hashes localmente, **ele não possui as chaves privadas dos outros 2 validadores** para forjar os 3 `CommitVotes` exigidos.
  3. Os 3 nós honestos rejeitam automaticamente qualquer proposta adulterada (HTTP 409) e a rotina `SyncAndHeal` (`internal/consensus/sync.go`, disparada periodicamente pelo `recovery.go`) detecta a corrupção em disco, baixa a cadeia canônica da supermaioria, valida todos os blocos desde o gênese, substitui `blockchain.json` atomicamente e reconstrói o `LedgerState`.

### 2.5. Reputação Imutável (*Append-Only*) e Auditoria Independente
* Avaliações (`RATING` 1–5), denúncias (`COMPLAINT`), cancelamentos tardios (`LATE_CANCEL`), cancelamentos de motorista (`DRIVER_CANCEL`) e ausências (`NO_SHOW_PASSENGER` / `NO_SHOW_DRIVER`) são gravados permanentemente vinculados à **chave pública do usuário** — nunca à empresa. Se um motorista migrar de empresa, todo o histórico o acompanha e aparece automaticamente na busca de itinerários (`SEARCH_ITINERARY`).
* A máquina de estados bloqueia edição/exclusão, exige participação real no `booking_id` (impedindo avaliações falsas de quem não viajou) e impede avaliação duplicada.
* Qualquer participante pode auditar o histórico completo de um itinerário, conta ou usuário via `cmd/auditor` ou nos menus dos clientes, verificando hashes, assinaturas e conservação de valor diretamente nos blocos, sem depender de nenhuma empresa específica.

---

## 3. Regras de Negócio Determinísticas

Todas as regras utilizam exclusivamente o `TimestampUnix` assinado dentro da transação (nunca `time.Now()` local na validação):

* **Conclusão de Viagem (`TX_COMPLETE_TRIP`):** transfere o valor em escrow para todos os motoristas de cada trecho em **uma única operação atômica** (split payment tudo-ou-nada).
* **Cancelamento pelo Passageiro (`TX_CANCEL_TRIP`):**
  * Antecedência $\ge 2$ horas (`7200s`): devolução de **100%** ao passageiro.
  * Cancelamento tardio ($< 2$ horas): retenção de **30%** distribuída proporcionalmente aos motoristas + devolução de **70%** ao passageiro + registro automático de `LATE_CANCEL`.
* **Cancelamento pelo Motorista (`TX_CANCEL_TRIP`):** devolução de **100%** ao passageiro + registro automático de `DRIVER_CANCEL`.
* **Ausência no Embarque (`TX_NO_SHOW`):**
  * Passageiro ausente: **100%** repassado aos motoristas + registro `NO_SHOW_PASSENGER`.
  * Motorista ausente: **100%** devolvido ao passageiro + registro grave `NO_SHOW_DRIVER`.

---

## 4. Pré-requisitos

* **Go 1.22+** (para execução local e testes): `go version`
* **Docker + Docker Compose v2+** (para execução em contêineres isolados): `docker compose version`

---

## 5. Execução Local (Go direto)

Abra 4 terminais na raiz do repositório e suba os 4 nós validadores:

```bash
# Terminal 1
go run cmd/server/main.go SERVER_A

# Terminal 2
go run cmd/server/main.go SERVER_B

# Terminal 3
go run cmd/server/main.go SERVER_C

# Terminal 4
go run cmd/server/main.go SERVER_D
```

Verifique o status PBFT dos 4 nós:
```bash
curl http://localhost:9080/p2p/status
curl http://localhost:9081/p2p/status
curl http://localhost:9082/p2p/status
curl http://localhost:9083/p2p/status
```

---

## 6. Execução com Docker Compose (4 contêineres isolados)

```bash
# Compila e sobe os 4 validadores (server_a..server_d) + clientes
docker compose up --build -d

# Abrir cliente Motorista interativo
docker compose run --rm driver_client

# Abrir cliente Passageiro interativo
docker compose run --rm passenger_client

# Simular queda de 1 nó (rede continua operando com quórum 3/4)
docker compose stop server_d

# Religar o nó (sincroniza automaticamente via SyncAndHeal)
docker compose start server_d

# Encerrar tudo
docker compose down
```

---

## 7. Execução em 4 Máquinas Distintas do Laboratório

Suponha 4 PCs no laboratório (LARSID/LADICA) com IPs `192.168.1.10` (`SERVER_A`), `.11` (`SERVER_B`), `.12` (`SERVER_C`) e `.13` (`SERVER_D`). Em cada máquina, construa a imagem e rode seu contêiner isolado:

```bash
docker build --target server -t vaijunto-server .
```

**Máquina 1 (`SERVER_A`):**
```bash
docker run -d --name server_a -p 8080:8080 -p 9080:9080 \
  -e SERVER_ID=SERVER_A -e CLIENT_PORT=8080 -e INTERNAL_PORT=9080 \
  -e PEERS="SERVER_B=http://192.168.1.11:9081,SERVER_C=http://192.168.1.12:9082,SERVER_D=http://192.168.1.13:9083" \
  -v "$(pwd)/data/SERVER_A:/app/data/SERVER_A" vaijunto-server
```

**Máquina 2 (`SERVER_B`):**
```bash
docker run -d --name server_b -p 8081:8081 -p 9081:9081 \
  -e SERVER_ID=SERVER_B -e CLIENT_PORT=8081 -e INTERNAL_PORT=9081 \
  -e PEERS="SERVER_A=http://192.168.1.10:9080,SERVER_C=http://192.168.1.12:9082,SERVER_D=http://192.168.1.13:9083" \
  -v "$(pwd)/data/SERVER_B:/app/data/SERVER_B" vaijunto-server
```

**Máquina 3 (`SERVER_C`):**
```bash
docker run -d --name server_c -p 8082:8082 -p 9082:9082 \
  -e SERVER_ID=SERVER_C -e CLIENT_PORT=8082 -e INTERNAL_PORT=9082 \
  -e PEERS="SERVER_A=http://192.168.1.10:9080,SERVER_B=http://192.168.1.11:9081,SERVER_D=http://192.168.1.13:9083" \
  -v "$(pwd)/data/SERVER_C:/app/data/SERVER_C" vaijunto-server
```

**Máquina 4 (`SERVER_D`):**
```bash
docker run -d --name server_d -p 8083:8083 -p 9083:9083 \
  -e SERVER_ID=SERVER_D -e CLIENT_PORT=8083 -e INTERNAL_PORT=9083 \
  -e PEERS="SERVER_A=http://192.168.1.10:9080,SERVER_B=http://192.168.1.11:9081,SERVER_C=http://192.168.1.12:9082" \
  -v "$(pwd)/data/SERVER_D:/app/data/SERVER_D" vaijunto-server
```

*(As chaves públicas dos 4 validadores são derivadas deterministicamente via `CONSORTIUM_SEED`, eliminando cópia manual de arquivos entre as máquinas. Lembre-se de liberar as portas 8080–8083 e 9080–9083 no firewall.)*

---

## 8. Usando os Clientes Interativos e o Auditor

### Cliente Motorista (`cmd/driver-client`)
```bash
go run cmd/driver-client/main.go
```
Gera/carrega automaticamente sua carteira Ed25519 em `data/wallets/` e permite ofertar/listar/cancelar caronas, consultar saldo e extrato, resgatar créditos (`TX_BURN`), registrar ausência de passageiro (`TX_NO_SHOW`), consultar reputação portável e auditar itinerários.

### Cliente Passageiro (`cmd/passenger-client`)
```bash
go run cmd/passenger-client/main.go
```
Gera/carrega automaticamente sua carteira Ed25519 e permite solicitar recarga (`TX_MINT`), buscar itinerários (exibindo reputação on-chain dos motoristas), reservar com 2PC + Escrow atômico, cancelar com regras de 2h aplicadas pela rede, concluir viagem (split atômico), avaliar/denunciar motoristas, registrar ausência de motorista e auditar a blockchain.

### Auditor Independente (`cmd/auditor`)
Consulta diretamente os endpoints `/p2p/status` e `/p2p/chain` dos nós, valida criptograficamente todos os blocos (SHA-256 + quórum $\ge 3/4$ + conservação de valor) sem depender de nenhuma empresa:
```bash
# Auditoria geral dos 4 nós locais
go run cmd/auditor/main.go

# Auditar itinerário, conta ou reputação específica (local ou em IPs remotos)
go run cmd/auditor/main.go \
  -nodes "http://192.168.1.10:9080,http://192.168.1.11:9081,http://192.168.1.12:9082,http://192.168.1.13:9083" \
  -booking SERVER_C_BOOK_001
```

---

## 9. Scripts de Teste e Demonstração da Arguição

### Simulador Geral Completo da Apresentação (`cmd/simulator`)
Executa uma bateria completa de testes cobrindo **todos os requisitos, ataques de segurança, regras de negócio, carga concorrente, queda de nó, adulteração manual e auditoria independente**:
```bash
# Modo standalone (sobe os 4 servidores automaticamente em portas dedicadas e testa tudo, incluindo queda + adulteração)
go run cmd/simulator/main.go

# Modo contra servidores já rodando (localmente ou em 4 PCs do laboratório)
go run cmd/simulator/main.go -standalone=false \
  -servers "192.168.1.10:8080,192.168.1.11:8081,192.168.1.12:8082,192.168.1.13:8083" \
  -http "http://192.168.1.10:9080,http://192.168.1.11:9081,http://192.168.1.12:9082,http://192.168.1.13:9083" \
  -workers 12 -seats 4
```

### Demonstração Enxuta dos 7 Cenários (`cmd/blockchain-demo`)
```bash
go run cmd/blockchain-demo/main.go
```

### Suíte Completa de Testes Unitários e de Integração
```bash
go test -v -count=1 ./...
```
Cobre:
* `internal/crypto` — geração/persistência Ed25519, serialização canônica, assinatura válida, rejeição de 1 byte adulterado e falsificação de chave.
* `internal/blockchain` — economia de tokens, conservação de valor, gasto duplo, escrow + split, regras de cancelamento ($\ge 2$h e $< 2$h), *no-show*, reputação *append-only* e detecção de adulteração em disco.
* `internal/consensus` — consenso PBFT com 4 nós, operação com 1 nó offline + sync, rejeição de bloco adulterado e auto-cura automática.
* `internal/domain` — precedência e preempção de Lamport no 2PC.
* `internal/server` — validação anti-replay/assinatura na entrada, cancelamento multi-servidor e fluxo E2E completo nos 4 servidores.

---

## 10. Estrutura do Projeto

```text
PBL_REDES3/
├── cmd/
│   ├── server/             # Servidor validador (TCP + HTTP REST + P2P PBFT)
│   ├── driver-client/      # Portal CLI do Motorista com carteira Ed25519
│   ├── passenger-client/   # Portal CLI do Passageiro com carteira Ed25519
│   ├── auditor/            # Auditor independente da blockchain
│   ├── blockchain-demo/    # Demonstração enxuta dos 7 cenários da arguição
│   └── simulator/          # Simulador geral completo (segurança, regras, carga concorrente, falha e adulteração)
├── internal/
│   ├── crypto/             # Carteiras Ed25519, SHA-256 e serialização canônica
│   ├── blockchain/         # Regras determinísticas, structs, máquina de estados e cadeia
│   ├── consensus/          # Motor PBFT (Propose/Prepare/Commit), P2P HTTP e SyncAndHeal
│   ├── domain/             # Caronas, BFS de itinerários, repositório e log 2PC/Lamport
│   ├── protocol/           # Mensagens TCP e assinatura canônica de Requests
│   ├── cluster/            # Cliente REST interno entre empresas
│   ├── concurrency/        # Relógio lógico de Lamport e fila de requisições
│   └── server/             # Listener TCP, auth anti-replay, ledger handlers, HTTP interno e recovery
├── docs/
│   ├── arquitetura-blockchain.md
│   └── api-rest-consorcio.md
├── Dockerfile
├── docker-compose.yml
├── go.mod                  # Zero dependências externas (Go 1.22 stdlib)
└── README.md
```
