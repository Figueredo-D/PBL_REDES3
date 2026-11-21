package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Figueredo-D/PBL_REDES/internal/blockchain"
	"github.com/Figueredo-D/PBL_REDES/internal/crypto"
	"github.com/Figueredo-D/PBL_REDES/internal/domain"
	"github.com/Figueredo-D/PBL_REDES/internal/protocol"
)

const (
	colorReset  = "\033[0m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorCyan   = "\033[36m"
	colorWhite  = "\033[97m"
)

type Client struct {
	address string
	conn    net.Conn
	reader  *bufio.Reader
	reqSeq  uint64
}

func NewClient(address string) (*Client, error) {
	c := &Client{address: address}
	if err := c.connect(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Client) connect() error {
	if c.conn != nil {
		_ = c.conn.Close()
	}
	conn, err := net.DialTimeout("tcp", c.address, 3*time.Second)
	if err != nil {
		return err
	}
	c.conn = conn
	c.reader = bufio.NewReader(conn)
	return nil
}

func (c *Client) roundTrip(reqBytes []byte) (*protocol.Response, error) {
	_ = c.conn.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := c.conn.Write(reqBytes); err != nil {
		return nil, err
	}
	respBytes, err := c.reader.ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	var resp protocol.Response
	if err := json.Unmarshal(respBytes, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Send envia uma requisição TCP; se wallet != nil e sign == true, assina com Ed25519 + Nonce + Timestamp.
func (c *Client) Send(action string, wallet *crypto.Wallet, sign bool, payload interface{}) (*protocol.Response, error) {
	var payloadString string
	if payload != nil {
		b, _ := json.Marshal(payload)
		payloadString = string(b)
	}

	req := protocol.Request{
		Action: action,
		Token:  wallet.PublicKey,
		Data:   payloadString,
	}
	if sign {
		c.reqSeq++
		req.SenderPubKey = wallet.PublicKey
		req.Nonce = uint64(time.Now().UnixNano()) + c.reqSeq
		req.Timestamp = time.Now().Unix()
		if err := protocol.SignRequest(&req, wallet.PrivateKey); err != nil {
			return nil, fmt.Errorf("falha ao assinar requisição: %w", err)
		}
	}

	reqBytes, _ := json.Marshal(req)
	reqBytes = append(reqBytes, '\n')

	resp, err := c.roundTrip(reqBytes)
	if err == nil {
		return resp, nil
	}
	if cerr := c.connect(); cerr != nil {
		return nil, fmt.Errorf("servidor indisponível: %w", cerr)
	}
	return c.roundTrip(reqBytes)
}

func (c *Client) Close() {
	if c.conn != nil {
		_ = c.conn.Close()
	}
}

func resolveServerAddr(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	if !strings.Contains(addr, ":") {
		return addr + ":8080"
	}
	return addr
}

func defaultNodeAddr(envKey, localFallback string) string {
	if val := strings.TrimSpace(os.Getenv(envKey)); val != "" {
		return resolveServerAddr(val)
	}
	return localFallback
}

func selectAndConnect(scanner *bufio.Scanner, initialAddr string) (*Client, string, string) {
	addrA := defaultNodeAddr("SERVER_A_ADDR", "localhost:8080")
	addrB := defaultNodeAddr("SERVER_B_ADDR", "localhost:8081")
	addrC := defaultNodeAddr("SERVER_C_ADDR", "localhost:8082")
	addrD := defaultNodeAddr("SERVER_D_ADDR", "localhost:8083")

	serverAddr := initialAddr
	nodeLabel := "REMOTO"

	for {
		if serverAddr == "" {
			fmt.Println()
			fmt.Printf("%s+==============================================================================+%s\n", colorCyan, colorReset)
			fmt.Printf("%s|%s                 %sSELECIONE O SERVIDOR DO CONSORCIO (EMPRESA)%s                  %s|%s\n", colorCyan, colorReset, colorBold, colorReset, colorCyan, colorReset)
			fmt.Printf("%s+------------------------------------------------------------------------------+%s\n", colorCyan, colorReset)
			fmt.Printf("%s|%s   %s[1]%s  Empresa A  -  Servidor A   %s(%-22s)%s                   %s|%s\n", colorCyan, colorReset, colorBold+colorGreen, colorReset, colorDim, addrA, colorReset, colorCyan, colorReset)
			fmt.Printf("%s|%s   %s[2]%s  Empresa B  -  Servidor B   %s(%-22s)%s                   %s|%s\n", colorCyan, colorReset, colorBold+colorBlue, colorReset, colorDim, addrB, colorReset, colorCyan, colorReset)
			fmt.Printf("%s|%s   %s[3]%s  Empresa C  -  Servidor C   %s(%-22s)%s                   %s|%s\n", colorCyan, colorReset, colorBold+colorYellow, colorReset, colorDim, addrC, colorReset, colorCyan, colorReset)
			fmt.Printf("%s|%s   %s[4]%s  Empresa D  -  Servidor D   %s(%-22s)%s                   %s|%s\n", colorCyan, colorReset, colorBold+colorCyan, colorReset, colorDim, addrD, colorReset, colorCyan, colorReset)
			fmt.Printf("%s|%s   %s[5]%s  Outro endereco (Host:Porta remoto)                                    %s|%s\n", colorCyan, colorReset, colorBold, colorReset, colorCyan, colorReset)
			fmt.Printf("%s+==============================================================================+%s\n", colorCyan, colorReset)
			fmt.Printf(" %s>%s Escolha o servidor (1-5) [padrao: 1]: ", colorCyan+colorBold, colorReset)

			if !scanner.Scan() {
				os.Exit(0)
			}
			switch strings.TrimSpace(scanner.Text()) {
			case "2":
				serverAddr, nodeLabel = addrB, "SERVER_B"
			case "3":
				serverAddr, nodeLabel = addrC, "SERVER_C"
			case "4":
				serverAddr, nodeLabel = addrD, "SERVER_D"
			case "5":
				fmt.Printf(" %s>%s Digite o endereco do servidor (ex: 192.168.1.10:8080): ", colorCyan+colorBold, colorReset)
				if !scanner.Scan() {
					os.Exit(0)
				}
				customAddr := resolveServerAddr(scanner.Text())
				if customAddr == "" {
					serverAddr, nodeLabel = addrA, "SERVER_A"
				} else {
					serverAddr, nodeLabel = customAddr, "REMOTO"
				}
			default:
				serverAddr, nodeLabel = addrA, "SERVER_A"
			}
		} else {
			switch serverAddr {
			case addrA, "localhost:8080":
				nodeLabel = "SERVER_A"
			case addrB, "localhost:8081":
				nodeLabel = "SERVER_B"
			case addrC, "localhost:8082":
				nodeLabel = "SERVER_C"
			case addrD, "localhost:8083":
				nodeLabel = "SERVER_D"
			default:
				nodeLabel = "REMOTO"
			}
		}

		client, err := NewClient(serverAddr)
		if err == nil {
			return client, serverAddr, nodeLabel
		}
		fmt.Printf("\n %s[ERRO DE CONEXAO]%s Nao foi possivel conectar em %s(%s)%s: %v\n",
			colorRed+colorBold, colorReset, colorBold, serverAddr, colorReset, err)
		serverAddr = ""
	}
}

func loadDriverWallet(scanner *bufio.Scanner, currentName string) (*crypto.Wallet, string) {
	if currentName != "" {
		fmt.Printf("\n %s>%s Digite o nome do Motorista (Enter para manter [%s]): ", colorCyan+colorBold, colorReset, currentName)
	} else {
		fmt.Printf("\n %s>%s Digite seu nome/identificador de Motorista (carteira Ed25519): ", colorCyan+colorBold, colorReset)
	}
	if !scanner.Scan() {
		os.Exit(0)
	}
	name := strings.TrimSpace(scanner.Text())
	if name == "" {
		if currentName != "" {
			name = currentName
		} else {
			name = "motorista_default"
		}
	}

	walletDir := strings.TrimSpace(os.Getenv("WALLET_DIR"))
	if walletDir == "" {
		walletDir = filepath.Join("data", "wallets")
	}
	safeName := strings.ReplaceAll(strings.ToLower(name), " ", "_")
	walletPath := filepath.Join(walletDir, "driver_"+safeName+".json")

	w, err := crypto.LoadOrCreateWallet(walletPath, name, crypto.RoleDriver)
	if err != nil {
		fmt.Printf(" %s[ERRO]%s Falha ao inicializar carteira: %v\n", colorRed, colorReset, err)
		os.Exit(1)
	}
	return w, name
}

func shortKey(pub string) string {
	if len(pub) <= 16 {
		return pub
	}
	return pub[:8] + "..." + pub[len(pub)-8:]
}

func printWelcomeBanner() {
	fmt.Println()
	fmt.Printf("%s+==============================================================================+%s\n", colorCyan, colorReset)
	fmt.Printf("%s|%s          %sVAIJUNTO COM BLOCKCHAIN - CONSORCIO DE CARONAS (PBFT)%s               %s|%s\n", colorCyan, colorReset, colorBold+colorWhite, colorReset, colorCyan, colorReset)
	fmt.Printf("%s|%s                      %sPORTAL INTERATIVO DO MOTORISTA%s                          %s|%s\n", colorCyan, colorReset, colorCyan+colorBold, colorReset, colorCyan, colorReset)
	fmt.Printf("%s+==============================================================================+%s\n", colorCyan, colorReset)
}

func printMenuItem(key, keyColor, label string) {
	const innerWidth = 78
	// Prefixo visual: "    [X]  " = 9 caracteres visíveis
	const labelWidth = innerWidth - 9
	fmt.Printf("%s|%s    %s[%s]%s  %s%s|%s\n",
		colorCyan, colorReset,
		keyColor, key, colorReset,
		padRight(label, labelWidth),
		colorCyan, colorReset)
}

func printMainMenu(name string, wallet *crypto.Wallet, nodeLabel, serverAddr string) {
	statusLine := fmt.Sprintf("Motorista: [%s] (%s) | Empresa: [%s]", name, shortKey(wallet.PublicKey), nodeLabel)
	fmt.Println()
	fmt.Printf("%s+==============================================================================+%s\n", colorCyan, colorReset)
	fmt.Printf("%s|%s  %s%s%s  %s|%s\n", colorCyan, colorReset, colorBold+colorWhite, padRight("PAINEL DO MOTORISTA", 74), colorReset, colorCyan, colorReset)
	fmt.Printf("%s|%s  %s%s%s  %s|%s\n", colorCyan, colorReset, colorDim, padRight(statusLine, 74), colorReset, colorCyan, colorReset)
	fmt.Printf("%s+------------------------------------------------------------------------------+%s\n", colorCyan, colorReset)
	printMenuItem("1", colorBold+colorGreen, "Ofertar Nova Carona")
	printMenuItem("2", colorBold+colorCyan, "Minhas Caronas Cadastradas")
	printMenuItem("3", colorBold+colorYellow, "Cancelar uma Carona")
	printMenuItem("4", colorBold+colorGreen, "Consultar Saldo & Extrato (Blockchain)")
	printMenuItem("5", colorBold+colorBlue, "Resgatar Creditos (TX_BURN)")
	printMenuItem("6", colorBold+colorYellow, "Registrar Ausencia de Passageiro (TX_NO_SHOW)")
	printMenuItem("7", colorBold+colorCyan, "Minha Reputacao & Auditoria Independente")
	printMenuItem("8", colorBold+colorBlue, "Trocar de Servidor / Trocar Motorista")
	printMenuItem("0", colorBold+colorRed, "Encerrar Sessao")
	fmt.Printf("%s+==============================================================================+%s\n", colorCyan, colorReset)
	fmt.Printf(" %s>%s Escolha uma opcao (0-8): ", colorCyan+colorBold, colorReset)
}

func fetchLedgerNonce(client *Client, wallet *crypto.Wallet) uint64 {
	resp, err := client.Send(protocol.ActionGetBalance, wallet, false, nil)
	if err != nil || resp.Status != "SUCCESS" {
		return 0
	}
	var data struct {
		Nonce uint64 `json:"nonce"`
	}
	_ = json.Unmarshal([]byte(resp.Data), &data)
	return data.Nonce
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)

	printWelcomeBanner()
	wallet, driverName := loadDriverWallet(scanner, "")

	var initialAddr string
	if len(os.Args) > 1 && !strings.HasPrefix(os.Args[1], "-") {
		initialAddr = resolveServerAddr(os.Args[1])
	} else if env := strings.TrimSpace(os.Getenv("SERVER_HOST")); env != "" {
		initialAddr = resolveServerAddr(env)
	} else if env := strings.TrimSpace(os.Getenv("SERVER_ADDR")); env != "" {
		initialAddr = resolveServerAddr(env)
	}

	client, serverAddr, nodeLabel := selectAndConnect(scanner, initialAddr)
	defer func() {
		if client != nil {
			client.Close()
		}
	}()

	fmt.Printf("\n %s[CONECTADO]%s Motorista %s[%s]%s | Chave Publica: %s%s%s\n",
		colorGreen+colorBold, colorReset, colorBold, driverName, colorReset, colorCyan, wallet.PublicKey, colorReset)

	for {
		printMainMenu(driverName, wallet, nodeLabel, serverAddr)
		if !scanner.Scan() {
			return
		}

		switch strings.TrimSpace(scanner.Text()) {
		case "1":
			handleOfferRide(client, scanner, wallet)
		case "2":
			handleListRides(client, wallet)
		case "3":
			handleCancelRide(client, scanner, wallet)
		case "4":
			handleBalanceAndAudit(client, wallet)
		case "5":
			handleBurnCredits(client, scanner, wallet, nodeLabel)
		case "6":
			handleReportPassengerNoShow(client, scanner, wallet)
		case "7":
			handleReputationAndAudit(client, scanner, wallet)
		case "8":
			wallet, driverName = loadDriverWallet(scanner, driverName)
			client.Close()
			client, serverAddr, nodeLabel = selectAndConnect(scanner, "")
		case "0":
			fmt.Printf("\n %sSessao do motorista encerrada com seguranca. Ate logo!%s\n\n", colorCyan+colorBold, colorReset)
			return
		default:
			fmt.Printf("\n %s[!] Opcao invalida. Digite um numero entre 0 e 8.%s\n", colorYellow, colorReset)
		}
	}
}

func handleOfferRide(client *Client, scanner *bufio.Scanner, wallet *crypto.Wallet) {
	fmt.Printf("\n %s--- OFERTAR NOVA CARONA ---%s\n", colorGreen+colorBold, colorReset)
	fmt.Printf(" %s>%s Cidades da rota separadas por virgula (ex: Salvador, Feira): ", colorCyan+colorBold, colorReset)
	if !scanner.Scan() {
		return
	}
	rawCities := strings.Split(scanner.Text(), ",")
	var route []string
	for _, c := range rawCities {
		if trimmed := strings.TrimSpace(c); trimmed != "" {
			route = append(route, trimmed)
		}
	}
	if len(route) < 2 {
		fmt.Printf(" %s[ERRO]%s Informe ao menos 2 cidades.\n", colorRed, colorReset)
		return
	}

	fmt.Printf(" %s>%s Data da viagem (AAAA-MM-DD): ", colorCyan+colorBold, colorReset)
	if !scanner.Scan() {
		return
	}
	date := strings.TrimSpace(scanner.Text())

	fmt.Printf(" %s>%s Horario de partida (HH:MM): ", colorCyan+colorBold, colorReset)
	if !scanner.Scan() {
		return
	}
	timeStr := strings.TrimSpace(scanner.Text())

	fmt.Printf(" %s>%s Quantidade de assentos: ", colorCyan+colorBold, colorReset)
	if !scanner.Scan() {
		return
	}
	seats, err := strconv.Atoi(strings.TrimSpace(scanner.Text()))
	if err != nil || seats <= 0 {
		fmt.Printf(" %s[ERRO]%s Quantidade de assentos invalida.\n", colorRed, colorReset)
		return
	}

	prices := make([]float64, len(route)-1)
	for i := 0; i < len(route)-1; i++ {
		fmt.Printf(" %s>%s Preco do trecho %s -> %s (R$): ", colorCyan+colorBold, colorReset, route[i], route[i+1])
		if !scanner.Scan() {
			return
		}
		p, err := strconv.ParseFloat(strings.ReplaceAll(strings.TrimSpace(scanner.Text()), ",", "."), 64)
		if err != nil || p <= 0 {
			fmt.Printf(" %s[ERRO]%s Preco invalido.\n", colorRed, colorReset)
			return
		}
		prices[i] = p
	}

	resp, err := client.Send(protocol.ActionOfferRide, wallet, true, protocol.OfferRideData{
		Route:         route,
		Date:          date,
		Time:          timeStr,
		TotalSeats:    seats,
		SegmentPrices: prices,
	})
	if err != nil {
		fmt.Printf(" %s[ERRO]%s %v\n", colorRed, colorReset, err)
		return
	}
	printServerResponse(resp)
}

func handleListRides(client *Client, wallet *crypto.Wallet) []*domain.Ride {
	resp, err := client.Send(protocol.ActionListRides, wallet, false, nil)
	if err != nil {
		fmt.Printf(" %s[ERRO]%s %v\n", colorRed, colorReset, err)
		return nil
	}
	var rides []*domain.Ride
	_ = json.Unmarshal([]byte(resp.Data), &rides)

	fmt.Printf("\n %s--- MINHAS CARONAS CADASTRADAS (%d) ---%s\n", colorCyan+colorBold, len(rides), colorReset)
	if len(rides) == 0 {
		fmt.Println(" Nenhuma carona cadastrada nesta empresa.")
		return nil
	}
	for i, r := range rides {
		fmt.Printf(" [%d] %s | Rota: %s | Data: %s %s\n", i+1, r.ID, strings.Join(r.Route, " -> "), r.Date, r.Time)
		for _, seg := range r.Segments {
			fmt.Printf("     - %s -> %s | R$ %.2f | Vagas: %d/%d\n", seg.From, seg.To, seg.Price, seg.AvailableSeats, r.TotalSeats)
		}
	}
	return rides
}

func handleCancelRide(client *Client, scanner *bufio.Scanner, wallet *crypto.Wallet) {
	rides := handleListRides(client, wallet)
	if len(rides) == 0 {
		return
	}
	fmt.Printf("\n %s>%s Digite o numero (#) ou ID da carona a cancelar (Enter para voltar): ", colorCyan+colorBold, colorReset)
	if !scanner.Scan() {
		return
	}
	in := strings.TrimSpace(scanner.Text())
	if in == "" {
		return
	}
	rideID := in
	if idx, err := strconv.Atoi(in); err == nil && idx >= 1 && idx <= len(rides) {
		rideID = rides[idx-1].ID
	}

	fmt.Printf(" %s>%s Se houver reserva (booking_id) ativa afetada, informe o ID para reembolso on-chain (ou Enter para pular): ", colorCyan+colorBold, colorReset)
	var cancelTxs []string
	if scanner.Scan() {
		if bid := strings.TrimSpace(scanner.Text()); bid != "" {
			nextNonce := fetchLedgerNonce(client, wallet) + 1
			tx, err := blockchain.NewSignedTransaction(wallet, blockchain.TxCancelTrip, nextNonce, time.Now().Unix(), blockchain.CancelTripPayload{
				BookingID: bid,
				ActorRole: "DRIVER",
				Reason:    "Carona cancelada pelo motorista",
			})
			if err == nil {
				raw, _ := json.Marshal(tx)
				cancelTxs = append(cancelTxs, string(raw))
			}
		}
	}

	resp, err := client.Send(protocol.ActionCancelRide, wallet, true, protocol.CancelRideData{
		RideID:    rideID,
		CancelTxs: cancelTxs,
	})
	if err != nil {
		fmt.Printf(" %s[ERRO]%s %v\n", colorRed, colorReset, err)
		return
	}
	printServerResponse(resp)
}

func handleBalanceAndAudit(client *Client, wallet *crypto.Wallet) {
	resp, err := client.Send(protocol.ActionAuditAccount, wallet, false, map[string]string{"pub_key": wallet.PublicKey})
	if err != nil {
		fmt.Printf(" %s[ERRO]%s %v\n", colorRed, colorReset, err)
		return
	}
	if resp.Status != "SUCCESS" {
		printServerResponse(resp)
		return
	}
	var data struct {
		BalanceCents   int64 `json:"balance_cents"`
		EscrowCents    int64 `json:"escrow_cents"`
		Nonce          uint64 `json:"nonce"`
		ChainHeight    uint64 `json:"chain_height"`
		ConservationOK bool   `json:"conservation_ok"`
		Transactions   []struct {
			BlockHeight uint64                 `json:"block_height"`
			Tx          blockchain.Transaction `json:"tx"`
		} `json:"transactions"`
	}
	_ = json.Unmarshal([]byte(resp.Data), &data)

	fmt.Printf("\n %s--- CARTEIRA BLOCKCHAIN (MOTORISTA) ---%s\n", colorGreen+colorBold, colorReset)
	fmt.Printf(" Chave Publica:    %s\n", wallet.PublicKey)
	fmt.Printf(" Saldo Disponivel: R$ %.2f (%d centavos)\n", float64(data.BalanceCents)/100.0, data.BalanceCents)
	fmt.Printf(" Nonce Confirmado: %d | Altura da Cadeia: #%d | Conservacao OK: %v\n", data.Nonce, data.ChainHeight, data.ConservationOK)
	fmt.Printf(" Historico (%d transacao(oes)):\n", len(data.Transactions))
	for _, t := range data.Transactions {
		fmt.Printf("   - Bloco #%d | %s | ID: %s\n", t.BlockHeight, t.Tx.Type, shortKey(t.Tx.ID))
	}
}

func handleBurnCredits(client *Client, scanner *bufio.Scanner, wallet *crypto.Wallet, nodeLabel string) {
	fmt.Printf("\n %s--- RESGATE DE CREDITOS (TX_BURN) ---%s\n", colorBlue+colorBold, colorReset)
	fmt.Printf(" %s>%s Valor a resgatar em R$ (ex: 50.00): ", colorCyan+colorBold, colorReset)
	if !scanner.Scan() {
		return
	}
	val, err := strconv.ParseFloat(strings.ReplaceAll(strings.TrimSpace(scanner.Text()), ",", "."), 64)
	if err != nil || val <= 0 {
		fmt.Printf(" %s[ERRO]%s Valor invalido.\n", colorRed, colorReset)
		return
	}
	cents := int64(math.Round(val * 100))
	nextNonce := fetchLedgerNonce(client, wallet) + 1

	tx, err := blockchain.NewSignedTransaction(wallet, blockchain.TxBurn, nextNonce, time.Now().Unix(), blockchain.BurnPayload{
		AmountCents: cents,
		CompanyID:   nodeLabel,
	})
	if err != nil {
		fmt.Printf(" %s[ERRO]%s %v\n", colorRed, colorReset, err)
		return
	}

	resp, err := client.Send(protocol.ActionBurnCredits, wallet, true, tx)
	if err != nil {
		fmt.Printf(" %s[ERRO]%s %v\n", colorRed, colorReset, err)
		return
	}
	printServerResponse(resp)
}

func handleReportPassengerNoShow(client *Client, scanner *bufio.Scanner, wallet *crypto.Wallet) {
	fmt.Printf("\n %s--- REGISTRAR AUSENCIA DE PASSAGEIRO (TX_NO_SHOW) ---%s\n", colorYellow+colorBold, colorReset)
	fmt.Printf(" %s>%s ID da reserva (booking_id): ", colorCyan+colorBold, colorReset)
	if !scanner.Scan() {
		return
	}
	bookingID := strings.TrimSpace(scanner.Text())
	if bookingID == "" {
		return
	}
	fmt.Printf(" %s>%s Motivo/Observacao: ", colorCyan+colorBold, colorReset)
	if !scanner.Scan() {
		return
	}
	reason := strings.TrimSpace(scanner.Text())

	nextNonce := fetchLedgerNonce(client, wallet) + 1
	tx, err := blockchain.NewSignedTransaction(wallet, blockchain.TxNoShow, nextNonce, time.Now().Unix(), blockchain.NoShowPayload{
		BookingID:  bookingID,
		AbsentRole: "PASSENGER",
		Reason:     reason,
	})
	if err != nil {
		fmt.Printf(" %s[ERRO]%s %v\n", colorRed, colorReset, err)
		return
	}
	resp, err := client.Send(protocol.ActionReportNoShow, wallet, true, tx)
	if err != nil {
		fmt.Printf(" %s[ERRO]%s %v\n", colorRed, colorReset, err)
		return
	}
	printServerResponse(resp)
}

func handleReputationAndAudit(client *Client, scanner *bufio.Scanner, wallet *crypto.Wallet) {
	fmt.Printf("\n %s--- REPUTACAO & AUDITORIA INDEPENDENTE ---%s\n", colorCyan+colorBold, colorReset)
	fmt.Println(" [1] Consultar minha reputacao (portavel entre empresas)")
	fmt.Println(" [2] Auditar um itinerario (booking_id)")
	fmt.Printf(" %s>%s Opcao: ", colorCyan+colorBold, colorReset)
	if !scanner.Scan() {
		return
	}
	switch strings.TrimSpace(scanner.Text()) {
	case "1":
		resp, err := client.Send(protocol.ActionGetReputation, wallet, false, map[string]string{"target_pub_key": wallet.PublicKey})
		if err != nil {
			fmt.Printf(" %s[ERRO]%s %v\n", colorRed, colorReset, err)
			return
		}
		printPrettyJSON(resp.Data)
	case "2":
		fmt.Printf(" %s>%s Digite o booking_id: ", colorCyan+colorBold, colorReset)
		if !scanner.Scan() {
			return
		}
		resp, err := client.Send(protocol.ActionAuditItinerary, wallet, false, map[string]string{"booking_id": strings.TrimSpace(scanner.Text())})
		if err != nil {
			fmt.Printf(" %s[ERRO]%s %v\n", colorRed, colorReset, err)
			return
		}
		printPrettyJSON(resp.Data)
	default:
		fmt.Printf(" %s[!] Opcao invalida.%s\n", colorYellow, colorReset)
	}
}

func printPrettyJSON(raw string) {
	var parsed any
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		fmt.Println(raw)
		return
	}
	pretty, err := json.MarshalIndent(parsed, " ", "  ")
	if err != nil {
		fmt.Println(raw)
		return
	}
	fmt.Println(" " + string(pretty))
}

func printServerResponse(resp *protocol.Response) {
	if resp == nil {
		return
	}
	if resp.Status == "SUCCESS" {
		fmt.Printf("\n %s[OK]%s %s\n", colorGreen+colorBold, colorReset, resp.Message)
	} else {
		fmt.Printf("\n %s[ERRO %s]%s %s\n", colorRed+colorBold, resp.Code, colorReset, resp.Message)
	}
}

func padRight(s string, width int) string {
	l := utf8.RuneCountInString(s)
	if l >= width {
		return s[:width]
	}
	return s + strings.Repeat(" ", width-l)
}
