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

func loadPassengerWallet(scanner *bufio.Scanner, currentName string) (*crypto.Wallet, string) {
	if currentName != "" {
		fmt.Printf("\n %s>%s Digite o nome do Passageiro (Enter para manter [%s]): ", colorCyan+colorBold, colorReset, currentName)
	} else {
		fmt.Printf("\n %s>%s Digite seu nome/identificador de Passageiro (carteira Ed25519): ", colorCyan+colorBold, colorReset)
	}
	if !scanner.Scan() {
		os.Exit(0)
	}
	name := strings.TrimSpace(scanner.Text())
	if name == "" {
		if currentName != "" {
			name = currentName
		} else {
			name = "passageiro_default"
		}
	}

	walletDir := strings.TrimSpace(os.Getenv("WALLET_DIR"))
	if walletDir == "" {
		walletDir = filepath.Join("data", "wallets")
	}
	safeName := strings.ReplaceAll(strings.ToLower(name), " ", "_")
	walletPath := filepath.Join(walletDir, "passenger_"+safeName+".json")

	w, err := crypto.LoadOrCreateWallet(walletPath, name, crypto.RolePassenger)
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
	fmt.Printf("%s|%s                     %sPORTAL INTERATIVO DO PASSAGEIRO%s                          %s|%s\n", colorCyan, colorReset, colorCyan+colorBold, colorReset, colorCyan, colorReset)
	fmt.Printf("%s+==============================================================================+%s\n", colorCyan, colorReset)
}

func printMenuItem(key, keyColor, label string) {
	const innerWidth = 78
	const labelWidth = innerWidth - 9
	fmt.Printf("%s|%s    %s[%s]%s  %s%s|%s\n",
		colorCyan, colorReset,
		keyColor, key, colorReset,
		padRight(label, labelWidth),
		colorCyan, colorReset)
}

func printMainMenu(name string, wallet *crypto.Wallet, nodeLabel string) {
	statusLine := fmt.Sprintf("Passageiro: [%s] (%s) | Empresa: [%s]", name, shortKey(wallet.PublicKey), nodeLabel)
	fmt.Println()
	fmt.Printf("%s+==============================================================================+%s\n", colorCyan, colorReset)
	fmt.Printf("%s|%s  %s%s%s  %s|%s\n", colorCyan, colorReset, colorBold+colorWhite, padRight("PAINEL DO PASSAGEIRO", 74), colorReset, colorCyan, colorReset)
	fmt.Printf("%s|%s  %s%s%s  %s|%s\n", colorCyan, colorReset, colorDim, padRight(statusLine, 74), colorReset, colorCyan, colorReset)
	fmt.Printf("%s+------------------------------------------------------------------------------+%s\n", colorCyan, colorReset)
	printMenuItem("1", colorBold+colorGreen, "Buscar e Reservar Itinerarios (BFS + 2PC + Escrow Blockchain)")
	printMenuItem("2", colorBold+colorCyan, "Minhas Reservas Efetuadas")
	printMenuItem("3", colorBold+colorYellow, "Cancelar Reserva (Regras 2h na Blockchain)")
	printMenuItem("4", colorBold+colorGreen, "Concluir Viagem e Liberar Pagamento (Split Atomico)")
	printMenuItem("5", colorBold+colorBlue, "Saldo & Recarga de Creditos (TX_MINT via Empresa)")
	printMenuItem("6", colorBold+colorCyan, "Avaliar ou Denunciar Motorista (TX_REPUTATION)")
	printMenuItem("7", colorBold+colorYellow, "Registrar Ausencia de Motorista (TX_NO_SHOW)")
	printMenuItem("8", colorBold+colorBlue, "Auditoria Independente (Itinerario / Conta / Usuario)")
	printMenuItem("9", colorBold, "Trocar de Servidor / Trocar Passageiro")
	printMenuItem("0", colorBold+colorRed, "Encerrar Sessao")
	fmt.Printf("%s+==============================================================================+%s\n", colorCyan, colorReset)
	fmt.Printf(" %s>%s Escolha uma opcao (0-9): ", colorCyan+colorBold, colorReset)
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
	wallet, passengerName := loadPassengerWallet(scanner, "")

	var initialAddr string
	if len(os.Args) > 1 && !strings.HasPrefix(os.Args[1], "-") {
		initialAddr = resolveServerAddr(os.Args[1])
	} else if env := strings.TrimSpace(os.Getenv("SERVER_HOST")); env != "" {
		initialAddr = resolveServerAddr(env)
	} else if env := strings.TrimSpace(os.Getenv("SERVER_ADDR")); env != "" {
		initialAddr = resolveServerAddr(env)
	}

	client, _, nodeLabel := selectAndConnect(scanner, initialAddr)
	defer func() {
		if client != nil {
			client.Close()
		}
	}()

	fmt.Printf("\n %s[CONECTADO]%s Passageiro %s[%s]%s | Chave Publica: %s%s%s\n",
		colorGreen+colorBold, colorReset, colorBold, passengerName, colorReset, colorCyan, wallet.PublicKey, colorReset)

	for {
		printMainMenu(passengerName, wallet, nodeLabel)
		if !scanner.Scan() {
			return
		}

		switch strings.TrimSpace(scanner.Text()) {
		case "1":
			handleSearchAndBook(client, scanner, wallet, nodeLabel)
		case "2":
			handleListBookings(client, wallet)
		case "3":
			handleCancelBooking(client, scanner, wallet)
		case "4":
			handleCompleteTrip(client, scanner, wallet)
		case "5":
			handleBalanceAndMint(client, scanner, wallet, nodeLabel)
		case "6":
			handleSubmitReputation(client, scanner, wallet)
		case "7":
			handleReportDriverNoShow(client, scanner, wallet)
		case "8":
			handleAuditMenu(client, scanner, wallet)
		case "9":
			wallet, passengerName = loadPassengerWallet(scanner, passengerName)
			client.Close()
			client, _, nodeLabel = selectAndConnect(scanner, "")
		case "0":
			fmt.Printf("\n %sSessao do passageiro encerrada com seguranca. Boa viagem!%s\n\n", colorCyan+colorBold, colorReset)
			return
		default:
			fmt.Printf("\n %s[!] Opcao invalida. Digite um numero entre 0 e 9.%s\n", colorYellow, colorReset)
		}
	}
}

func parseDepartureUnix(dateStr, timeStr string) int64 {
	t, err := time.ParseInLocation("2006-01-02 15:04", dateStr+" "+timeStr, time.Local)
	if err != nil {
		return time.Now().Add(4 * time.Hour).Unix()
	}
	return t.Unix()
}

func handleSearchAndBook(client *Client, scanner *bufio.Scanner, wallet *crypto.Wallet, nodeLabel string) {
	fmt.Printf("\n %s--- BUSCAR E RESERVAR ITINERARIOS ---%s\n", colorGreen+colorBold, colorReset)
	fmt.Printf(" %s>%s Origem: ", colorCyan+colorBold, colorReset)
	if !scanner.Scan() {
		return
	}
	origin := strings.TrimSpace(scanner.Text())

	fmt.Printf(" %s>%s Destino: ", colorCyan+colorBold, colorReset)
	if !scanner.Scan() {
		return
	}
	dest := strings.TrimSpace(scanner.Text())

	fmt.Printf(" %s>%s Data (AAAA-MM-DD): ", colorCyan+colorBold, colorReset)
	if !scanner.Scan() {
		return
	}
	date := strings.TrimSpace(scanner.Text())

	resp, err := client.Send(protocol.ActionSearchItinerary, wallet, false, protocol.SearchItineraryData{
		Origin: origin, Destination: dest, Date: date,
	})
	if err != nil {
		fmt.Printf(" %s[ERRO]%s %v\n", colorRed, colorReset, err)
		return
	}
	if resp.Status != "SUCCESS" {
		printServerResponse(resp)
		return
	}

	var itins []domain.ItineraryResult
	_ = json.Unmarshal([]byte(resp.Data), &itins)
	if len(itins) == 0 {
		fmt.Println(" Nenhum itinerario encontrado para os filtros informados.")
		return
	}

	fmt.Printf("\n %sItinerarios encontrados (%d):%s\n", colorBold, len(itins), colorReset)
	for i, it := range itins {
		fmt.Printf("\n [%d] Total: R$ %.2f | Saida: %s | Vagas: %d\n", i+1, it.TotalPrice, it.DepartureTime, it.AvailableSeats)
		for _, seg := range it.Segments {
			rep := it.DriverReputations[seg.DriverToken]
			fmt.Printf("     - %s -> %s (%s) | R$ %.2f | Motorista: %s | Nota: %.1f (%d aval., %d den., %d faltas)\n",
				seg.From, seg.To, seg.CompanyID, seg.Price, shortKey(seg.DriverToken),
				rep.AverageRating, rep.TotalRatings, rep.Complaints, rep.NoShows)
		}
	}

	fmt.Printf("\n %s>%s Escolha o numero do itinerario para reservar (Enter para cancelar): ", colorCyan+colorBold, colorReset)
	if !scanner.Scan() {
		return
	}
	idx, err := strconv.Atoi(strings.TrimSpace(scanner.Text()))
	if err != nil || idx < 1 || idx > len(itins) {
		return
	}
	chosen := itins[idx-1]

	// Monta e assina a TX_RESERVE_ESCROW para ser integrada atomicamente ao 2PC
	bookingID := fmt.Sprintf("%s_BOOK_%d", nodeLabel, time.Now().UnixNano())
	var escrowSegs []blockchain.EscrowSegment
	var totalCents int64
	for _, seg := range chosen.Segments {
		c := int64(math.Round(seg.Price * 100))
		totalCents += c
		escrowSegs = append(escrowSegs, blockchain.EscrowSegment{
			RideID:       seg.RideID,
			CompanyID:    seg.CompanyID,
			DriverPubKey: seg.DriverToken,
			From:         seg.From,
			To:           seg.To,
			AmountCents:  c,
		})
	}

	nextNonce := fetchLedgerNonce(client, wallet) + 1
	escrowTx, err := blockchain.NewSignedTransaction(wallet, blockchain.TxReserveEscrow, nextNonce, time.Now().Unix(), blockchain.ReserveEscrowPayload{
		BookingID:     bookingID,
		DepartureUnix: parseDepartureUnix(date, chosen.DepartureTime),
		TotalCents:    totalCents,
		Segments:      escrowSegs,
	})
	if err != nil {
		fmt.Printf(" %s[ERRO]%s Falha ao assinar escrow: %v\n", colorRed, colorReset, err)
		return
	}

	bookPayload := map[string]any{
		"itinerary": chosen,
		"signed_tx": escrowTx,
	}
	respBook, err := client.Send(protocol.ActionBookItinerary, wallet, true, bookPayload)
	if err != nil {
		fmt.Printf(" %s[ERRO]%s %v\n", colorRed, colorReset, err)
		return
	}
	printServerResponse(respBook)
}

func handleListBookings(client *Client, wallet *crypto.Wallet) []*domain.Booking {
	resp, err := client.Send(protocol.ActionListBookings, wallet, false, nil)
	if err != nil {
		fmt.Printf(" %s[ERRO]%s %v\n", colorRed, colorReset, err)
		return nil
	}
	var bookings []*domain.Booking
	_ = json.Unmarshal([]byte(resp.Data), &bookings)

	fmt.Printf("\n %s--- MINHAS RESERVAS (%d) ---%s\n", colorCyan+colorBold, len(bookings), colorReset)
	if len(bookings) == 0 {
		fmt.Println(" Nenhuma reserva registrada nesta empresa.")
		return nil
	}
	for i, b := range bookings {
		fmt.Printf(" [%d] %s | Status: [%s] | Total: R$ %.2f\n", i+1, b.ID, b.Status, b.Itinerary.TotalPrice)
		for _, seg := range b.Itinerary.Segments {
			fmt.Printf("     - %s -> %s (%s) | Motorista: %s\n", seg.From, seg.To, seg.CompanyID, shortKey(seg.DriverToken))
		}
	}
	return bookings
}

func handleCancelBooking(client *Client, scanner *bufio.Scanner, wallet *crypto.Wallet) {
	bookings := handleListBookings(client, wallet)
	if len(bookings) == 0 {
		return
	}
	fmt.Printf("\n %s>%s Numero (#) ou booking_id para cancelar: ", colorCyan+colorBold, colorReset)
	if !scanner.Scan() {
		return
	}
	in := strings.TrimSpace(scanner.Text())
	if in == "" {
		return
	}
	bookingID := in
	if idx, err := strconv.Atoi(in); err == nil && idx >= 1 && idx <= len(bookings) {
		bookingID = bookings[idx-1].ID
	}

	nextNonce := fetchLedgerNonce(client, wallet) + 1
	tx, err := blockchain.NewSignedTransaction(wallet, blockchain.TxCancelTrip, nextNonce, time.Now().Unix(), blockchain.CancelTripPayload{
		BookingID: bookingID,
		ActorRole: "PASSENGER",
		Reason:    "Cancelamento solicitado pelo passageiro",
	})
	if err != nil {
		fmt.Printf(" %s[ERRO]%s %v\n", colorRed, colorReset, err)
		return
	}
	rawTx, _ := json.Marshal(tx)

	resp, err := client.Send(protocol.ActionCancelBooking, wallet, true, protocol.CancelBookingData{
		BookingID: bookingID,
		SignedTx:  string(rawTx),
	})
	if err != nil {
		fmt.Printf(" %s[ERRO]%s %v\n", colorRed, colorReset, err)
		return
	}
	printServerResponse(resp)
}

func handleCompleteTrip(client *Client, scanner *bufio.Scanner, wallet *crypto.Wallet) {
	bookings := handleListBookings(client, wallet)
	if len(bookings) == 0 {
		return
	}
	fmt.Printf("\n %s>%s Numero (#) ou booking_id da viagem concluida: ", colorCyan+colorBold, colorReset)
	if !scanner.Scan() {
		return
	}
	in := strings.TrimSpace(scanner.Text())
	if in == "" {
		return
	}
	bookingID := in
	if idx, err := strconv.Atoi(in); err == nil && idx >= 1 && idx <= len(bookings) {
		bookingID = bookings[idx-1].ID
	}

	nextNonce := fetchLedgerNonce(client, wallet) + 1
	tx, err := blockchain.NewSignedTransaction(wallet, blockchain.TxCompleteTrip, nextNonce, time.Now().Unix(), blockchain.CompleteTripPayload{
		BookingID: bookingID,
	})
	if err != nil {
		fmt.Printf(" %s[ERRO]%s %v\n", colorRed, colorReset, err)
		return
	}
	resp, err := client.Send(protocol.ActionCompleteTrip, wallet, true, tx)
	if err != nil {
		fmt.Printf(" %s[ERRO]%s %v\n", colorRed, colorReset, err)
		return
	}
	printServerResponse(resp)
}

func handleBalanceAndMint(client *Client, scanner *bufio.Scanner, wallet *crypto.Wallet, nodeLabel string) {
	resp, err := client.Send(protocol.ActionGetBalance, wallet, false, nil)
	if err != nil {
		fmt.Printf(" %s[ERRO]%s %v\n", colorRed, colorReset, err)
		return
	}
	var bal struct {
		BalanceCents int64  `json:"balance_cents"`
		EscrowCents  int64  `json:"escrow_cents"`
		Nonce        uint64 `json:"nonce"`
		BlockHeight  uint64 `json:"block_height"`
	}
	_ = json.Unmarshal([]byte(resp.Data), &bal)

	fmt.Printf("\n %s--- SALDO & RECARGA (TX_MINT) ---%s\n", colorBlue+colorBold, colorReset)
	fmt.Printf(" Saldo Livre:       R$ %.2f\n", float64(bal.BalanceCents)/100.0)
	fmt.Printf(" Preso em Escrow:   R$ %.2f\n", float64(bal.EscrowCents)/100.0)
	fmt.Printf(" Nonce Confirmado:  %d | Altura da Blockchain: #%d\n", bal.Nonce, bal.BlockHeight)

	fmt.Printf("\n %s>%s Deseja solicitar recarga (R$) pela empresa %s? (Enter para voltar): ", colorCyan+colorBold, colorReset, nodeLabel)
	if !scanner.Scan() {
		return
	}
	raw := strings.TrimSpace(scanner.Text())
	if raw == "" {
		return
	}
	val, err := strconv.ParseFloat(strings.ReplaceAll(raw, ",", "."), 64)
	if err != nil || val <= 0 {
		fmt.Printf(" %s[ERRO]%s Valor invalido.\n", colorRed, colorReset)
		return
	}

	// Simula a confirmacao do deposito bancario assinada pela chave da empresa conectada (validador autorizado)
	seed := strings.TrimSpace(os.Getenv("CONSORTIUM_SEED"))
	if seed == "" {
		seed = "VAIJUNTO_CONSORTIUM_PBFT_2026"
	}
	companyWallet := crypto.GenerateDeterministicWallet(nodeLabel, crypto.RoleValidator, seed+":"+nodeLabel)

	mintResp, err := client.Send(protocol.ActionMintCredits, companyWallet, true, protocol.MintCreditsData{
		TargetPubKey: wallet.PublicKey,
		AmountCents:  int64(math.Round(val * 100)),
		CompanyID:    nodeLabel,
		ReferenceID:  fmt.Sprintf("PIX_%d", time.Now().Unix()),
	})
	if err != nil {
		fmt.Printf(" %s[ERRO]%s %v\n", colorRed, colorReset, err)
		return
	}
	printServerResponse(mintResp)
}

func handleSubmitReputation(client *Client, scanner *bufio.Scanner, wallet *crypto.Wallet) {
	fmt.Printf("\n %s--- AVALIAR OU DENUNCIAR MOTORISTA (TX_REPUTATION) ---%s\n", colorCyan+colorBold, colorReset)
	fmt.Printf(" %s>%s ID da reserva (booking_id): ", colorCyan+colorBold, colorReset)
	if !scanner.Scan() {
		return
	}
	bookingID := strings.TrimSpace(scanner.Text())

	fmt.Printf(" %s>%s Chave publica do motorista avaliado: ", colorCyan+colorBold, colorReset)
	if !scanner.Scan() {
		return
	}
	targetPub := strings.TrimSpace(scanner.Text())

	fmt.Printf(" %s>%s Tipo ([1] Avaliacao 1-5 | [2] Denuncia): ", colorCyan+colorBold, colorReset)
	if !scanner.Scan() {
		return
	}
	cat := blockchain.RepRating
	score := 0
	if strings.TrimSpace(scanner.Text()) == "2" {
		cat = blockchain.RepComplaint
	} else {
		fmt.Printf(" %s>%s Nota (1 a 5): ", colorCyan+colorBold, colorReset)
		if !scanner.Scan() {
			return
		}
		score, _ = strconv.Atoi(strings.TrimSpace(scanner.Text()))
	}

	fmt.Printf(" %s>%s Comentario: ", colorCyan+colorBold, colorReset)
	if !scanner.Scan() {
		return
	}
	comment := strings.TrimSpace(scanner.Text())

	nextNonce := fetchLedgerNonce(client, wallet) + 1
	tx, err := blockchain.NewSignedTransaction(wallet, blockchain.TxReputation, nextNonce, time.Now().Unix(), blockchain.ReputationPayload{
		BookingID:    bookingID,
		TargetPubKey: targetPub,
		Category:     cat,
		Score:        score,
		Comment:      comment,
	})
	if err != nil {
		fmt.Printf(" %s[ERRO]%s %v\n", colorRed, colorReset, err)
		return
	}
	resp, err := client.Send(protocol.ActionSubmitReputation, wallet, true, tx)
	if err != nil {
		fmt.Printf(" %s[ERRO]%s %v\n", colorRed, colorReset, err)
		return
	}
	printServerResponse(resp)
}

func handleReportDriverNoShow(client *Client, scanner *bufio.Scanner, wallet *crypto.Wallet) {
	fmt.Printf("\n %s--- REGISTRAR AUSENCIA DE MOTORISTA (TX_NO_SHOW) ---%s\n", colorYellow+colorBold, colorReset)
	fmt.Printf(" %s>%s ID da reserva (booking_id): ", colorCyan+colorBold, colorReset)
	if !scanner.Scan() {
		return
	}
	bookingID := strings.TrimSpace(scanner.Text())

	fmt.Printf(" %s>%s Chave publica do motorista ausente: ", colorCyan+colorBold, colorReset)
	if !scanner.Scan() {
		return
	}
	absentPub := strings.TrimSpace(scanner.Text())

	fmt.Printf(" %s>%s Motivo: ", colorCyan+colorBold, colorReset)
	if !scanner.Scan() {
		return
	}
	reason := strings.TrimSpace(scanner.Text())

	nextNonce := fetchLedgerNonce(client, wallet) + 1
	tx, err := blockchain.NewSignedTransaction(wallet, blockchain.TxNoShow, nextNonce, time.Now().Unix(), blockchain.NoShowPayload{
		BookingID:    bookingID,
		AbsentRole:   "DRIVER",
		AbsentPubKey: absentPub,
		Reason:       reason,
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

func handleAuditMenu(client *Client, scanner *bufio.Scanner, wallet *crypto.Wallet) {
	fmt.Printf("\n %s--- AUDITORIA INDEPENDENTE DA BLOCKCHAIN ---%s\n", colorBlue+colorBold, colorReset)
	fmt.Println(" [1] Auditar minha conta (saldo, escrow, extrato e conservacao)")
	fmt.Println(" [2] Auditar um itinerario (booking_id)")
	fmt.Println(" [3] Auditar reputacao de qualquer usuario (chave publica)")
	fmt.Printf(" %s>%s Opcao: ", colorCyan+colorBold, colorReset)
	if !scanner.Scan() {
		return
	}
	switch strings.TrimSpace(scanner.Text()) {
	case "1":
		resp, err := client.Send(protocol.ActionAuditAccount, wallet, false, map[string]string{"pub_key": wallet.PublicKey})
		if err == nil {
			fmt.Println(resp.Data)
		}
	case "2":
		fmt.Printf(" %s>%s booking_id: ", colorCyan+colorBold, colorReset)
		if scanner.Scan() {
			resp, err := client.Send(protocol.ActionAuditItinerary, wallet, false, map[string]string{"booking_id": strings.TrimSpace(scanner.Text())})
			if err == nil {
				fmt.Println(resp.Data)
			}
		}
	case "3":
		fmt.Printf(" %s>%s Chave publica do usuario: ", colorCyan+colorBold, colorReset)
		if scanner.Scan() {
			resp, err := client.Send(protocol.ActionAuditUser, wallet, false, map[string]string{"target_pub_key": strings.TrimSpace(scanner.Text())})
			if err == nil {
				fmt.Println(resp.Data)
			}
		}
	}
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
