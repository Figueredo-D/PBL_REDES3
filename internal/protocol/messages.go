package protocol

import (
	"fmt"

	"github.com/Figueredo-D/PBL_REDES/internal/crypto"
)

const (
	ActionAuthenticate    = "AUTHENTICATE"
	ActionOfferRide       = "OFFER_RIDE"
	ActionListRides       = "LIST_RIDES"
	ActionCancelRide      = "CANCEL_RIDE"
	ActionSearchItinerary = "SEARCH_ITINERARY"
	ActionBookItinerary   = "BOOK_ITINERARY"
	ActionCancelBooking   = "CANCEL_BOOKING"
	ActionListBookings    = "LIST_BOOKINGS"

	// Ações de economia de tokens, ciclo de viagem, reputação e auditoria (Problema 3 - Blockchain)
	ActionMintCredits      = "MINT_CREDITS"      // Privilegiada: apenas nós validadores (empresas)
	ActionBurnCredits      = "BURN_CREDITS"      // Resgate de créditos pelo motorista
	ActionGetBalance       = "GET_BALANCE"       // Consulta de saldo (leitura)
	ActionCompleteTrip     = "COMPLETE_TRIP"     // Conclusão de viagem e split atômico do escrow
	ActionReportNoShow     = "REPORT_NO_SHOW"    // Registro de ausência no embarque
	ActionSubmitReputation = "SUBMIT_REPUTATION" // Avaliação ou denúncia pós-viagem
	ActionGetReputation    = "GET_REPUTATION"    // Consulta de reputação (leitura)
	ActionAuditItinerary   = "AUDIT_ITINERARY"   // Auditoria de itinerário (leitura)
	ActionAuditAccount     = "AUDIT_ACCOUNT"     // Auditoria de saldo/extrato (leitura)
	ActionAuditUser        = "AUDIT_USER"        // Auditoria de histórico de usuário (leitura)

	// Ações do protocolo Two-Phase Commit (2PC) entre os nós do consórcio
	Action2PCPrepare = "2PC_PREPARE"
	Action2PCCommit  = "2PC_COMMIT"
	Action2PCAbort   = "2PC_ABORT"

	// Ação entre nós para devolver as vagas de uma reserva cancelada pelo passageiro.
	// Não usa 2PC: devolver uma vaga não conflita com outras operações e é idempotente por reserva.
	ActionReleaseSeats = "RELEASE_SEATS"

	// Ação enviada pelo servidor dono da carona para todos os parceiros do consórcio quando um
	// motorista cancela sua carona. Os parceiros devem: (1) devolver as vagas do trecho cancelado
	// em suas caronas que fazem parte de itinerários afetados, e (2) marcar como CANCELLED_BY_DRIVER
	// todas as reservas de passageiros seus que incluíam aquele trecho.
	ActionNotifyCancelRide = "NOTIFY_CANCEL_RIDE"
)

type Request struct {
	Action       string `json:"action"`
	Token        string `json:"token,omitempty"`
	Data         string `json:"data,omitempty"`
	SenderPubKey string `json:"sender_pub_key,omitempty"` // Chave pública Ed25519 (hex) de quem originou a operação
	Nonce        uint64 `json:"nonce,omitempty"`          // Contador sequencial por SenderPubKey (anti-replay)
	Timestamp    int64  `json:"timestamp,omitempty"`      // Timestamp Unix (segundos) gerado na origem
	Signature    string `json:"signature,omitempty"`      // Assinatura Ed25519 (hex) sobre o payload canônico da Request
}

// canonicalRequestEnvelope define exatamente os campos cobertos pela assinatura digital de uma Request.
type canonicalRequestEnvelope struct {
	Action       string `json:"action"`
	Data         string `json:"data"`
	Nonce        uint64 `json:"nonce"`
	SenderPubKey string `json:"sender_pub_key"`
	Timestamp    int64  `json:"timestamp"`
	Token        string `json:"token"`
}

// SigningPayload gera os bytes determinísticos que devem ser assinados e verificados para a Request.
// Cobre todos os campos relevantes da operação, incluindo Nonce e Timestamp.
func SigningPayload(req Request) ([]byte, error) {
	env := canonicalRequestEnvelope{
		Action:       req.Action,
		Data:         req.Data,
		Nonce:        req.Nonce,
		SenderPubKey: req.SenderPubKey,
		Timestamp:    req.Timestamp,
		Token:        req.Token,
	}
	return crypto.CanonicalSerialize(env)
}

// SignRequest assina a requisição com a chave privada Ed25519 (hex) e preenche req.Signature.
func SignRequest(req *Request, privKeyHex string) error {
	if req == nil {
		return fmt.Errorf("requisição nula")
	}
	payload, err := SigningPayload(*req)
	if err != nil {
		return err
	}
	sig, err := crypto.SignPayload(privKeyHex, payload)
	if err != nil {
		return err
	}
	req.Signature = sig
	return nil
}

// VerifyRequestSignature verifica a assinatura Ed25519 da Request contra req.SenderPubKey.
func VerifyRequestSignature(req Request) error {
	payload, err := SigningPayload(req)
	if err != nil {
		return err
	}
	return crypto.VerifySignature(req.SenderPubKey, payload, req.Signature)
}

type Response struct {
	Status  string `json:"status"` // "SUCCESS", "ERROR", "VOTE_COMMIT", "VOTE_ABORT"
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
	Data    string `json:"data,omitempty"`
}

type OfferRideData struct {
	Route         []string  `json:"route"`
	Date          string    `json:"date"`
	Time          string    `json:"time"`
	TotalSeats    int       `json:"total_seats"`
	SegmentPrices []float64 `json:"segment_prices"`
}

type CancelRideData struct {
	RideID string `json:"ride_id"`
}

// NotifyCancelRideData é o payload de POST /internal/notify-cancel-ride.
// O servidor dono da carona envia para cada parceiro do consórcio quando um motorista
// cancela a carona. Os segmentos descrevem os trechos afetados para que os parceiros
// possam devolver as vagas e marcar as reservas impactadas.
type NotifyCancelRideData struct {
	RideID   string        `json:"ride_id"`   // ID da carona cancelada (pertence ao servidor remetente)
	Segments []SegmentInfo `json:"segments"`  // Trechos da carona, para identificar reservas afetadas
}

type SearchItineraryData struct {
	Origin      string `json:"origin"`
	Destination string `json:"destination"`
	Date        string `json:"date"`
}

type BookItineraryData struct {
	ItineraryID string   `json:"itinerary_id"`
	SegmentIDs  []string `json:"segment_ids,omitempty"`
}

type CancelBookingData struct {
	BookingID string `json:"booking_id"`
}

// ReleaseSeatsData é o payload de POST /internal/release. O nó que guarda a reserva cancelada envia
// o ID dela e os trechos; cada empresa devolve apenas os trechos das suas caronas, uma vez por reserva.
type ReleaseSeatsData struct {
	BookingID string        `json:"booking_id"`
	Segments  []SegmentInfo `json:"segments"`
}

// Payload da Fase 1 do 2PC (Prepare). LamportTime e CoordinatorID definem a precedência
// da transação na fila de cada participante: menor timestamp primeiro, desempate pelo ID do coordenador.
type TwoPCPrepareData struct {
	TransactionID string          `json:"transaction_id"`
	LamportTime   int64           `json:"lamport_time"`
	CoordinatorID string          `json:"coordinator_id"`
	Itinerary     ItineraryOption `json:"itinerary"`
}

type SegmentInfo struct {
	RideID         string  `json:"ride_id"`
	CompanyID      string  `json:"company_id"` // Empresa (nó) dona deste trecho, usada pelo peer para decidir se o trecho é local
	DriverToken    string  `json:"driver_token"`
	From           string  `json:"from"`
	To             string  `json:"to"`
	DepartureTime  string  `json:"departure_time"`
	Price          float64 `json:"price"`
	AvailableSeats int     `json:"available_seats"`
}

type ItineraryOption struct {
	ItineraryID    string        `json:"itinerary_id"`
	Segments       []SegmentInfo `json:"segments"`
	TotalPrice     float64       `json:"total_price"`
	DepartureTime  string        `json:"departure_time"`
	AvailableSeats int           `json:"available_seats"`
	Drivers        []string      `json:"drivers"`
}

type Booking struct {
	ID             string          `json:"id"`
	PassengerToken string          `json:"passenger_token"`
	Itinerary      ItineraryOption `json:"itinerary"`
	Date           string          `json:"date"`
	Status         string          `json:"status"` // "CONFIRMED", "CANCELLED", "CANCELLED_BY_DRIVER"
}

// MintCreditsData representa o payload de recarga de créditos (TX_MINT) assinada pela empresa.
type MintCreditsData struct {
	TargetPubKey string `json:"target_pub_key"`
	AmountCents  int64  `json:"amount_cents"`
	CompanyID    string `json:"company_id"`
	ReferenceID  string `json:"reference_id"`
}

// BurnCreditsData representa o payload de resgate de créditos (TX_BURN) assinado pelo motorista.
type BurnCreditsData struct {
	AmountCents int64  `json:"amount_cents"`
	CompanyID   string `json:"company_id"`
}

// CompleteTripData representa o payload de conclusão de viagem (TX_COMPLETE_TRIP).
type CompleteTripData struct {
	BookingID string `json:"booking_id"`
}

// ReportNoShowData representa o payload de registro de ausência no embarque (TX_NO_SHOW).
type ReportNoShowData struct {
	BookingID    string `json:"booking_id"`
	AbsentRole   string `json:"absent_role"`    // "PASSENGER" ou "DRIVER"
	AbsentPubKey string `json:"absent_pub_key"` // Chave pública de quem faltou
	Reason       string `json:"reason,omitempty"`
}

// SubmitReputationData representa o payload de avaliação ou denúncia (TX_REPUTATION).
type SubmitReputationData struct {
	BookingID    string `json:"booking_id"`
	TargetPubKey string `json:"target_pub_key"`
	Category     string `json:"category"` // "RATING" ou "COMPLAINT"
	Score        int    `json:"score"`    // 1..5 para RATING; 0 para COMPLAINT
	Comment      string `json:"comment"`
}
