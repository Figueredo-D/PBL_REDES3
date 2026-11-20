package blockchain

// Constantes determinísticas do consórcio VaiJunto.
// Todos os nós validam exatamente estas mesmas regras sem usar time.Now() na transição de estado.
const (
	// Consenso PBFT (N = 3f + 1, com f = 1)
	TotalValidators = 4
	MaxFaultyNodes  = 1
	QuorumSize      = 3 // 2f + 1 (>= 2/3 dos validadores)

	// Bloco Gênese determinístico
	GenesisPrevHash      = "0000000000000000000000000000000000000000000000000000000000000000"
	GenesisTimestampUnix = int64(1700000000)

	// Política de Cancelamento do Consórcio
	FreeCancelWindowSeconds int64 = 2 * 3600 // >= 2 horas antes do embarque: devolução de 100%
	LateCancelRetentionPct  int64 = 30       // < 2 horas: 30% retido e distribuído aos motoristas
	LateCancelRefundPct     int64 = 70       // < 2 horas: 70% devolvido ao passageiro

	// Política de Reputação
	MinRatingScore = 1
	MaxRatingScore = 5
)
