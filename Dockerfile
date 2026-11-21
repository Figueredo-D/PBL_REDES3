# ==========================================
# ETAPA 1: Compilação dos binários em Go
# ==========================================
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Instala certificados TLS caso necessário para chamadas HTTP
RUN apk add --no-cache ca-certificates

COPY go.mod ./
COPY . .

# Compila os executáveis estáticos (100% Go stdlib, sem dependências externas)
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/bin/server ./cmd/server/main.go && \
    CGO_ENABLED=0 GOOS=linux go build -o /app/bin/driver-client ./cmd/driver-client/main.go && \
    CGO_ENABLED=0 GOOS=linux go build -o /app/bin/passenger-client ./cmd/passenger-client/main.go && \
    CGO_ENABLED=0 GOOS=linux go build -o /app/bin/auditor ./cmd/auditor/main.go && \
    CGO_ENABLED=0 GOOS=linux go build -o /app/bin/blockchain-demo ./cmd/blockchain-demo/main.go

# ==========================================
# ETAPA 2: Imagem do Servidor Validador
# ==========================================
FROM alpine:latest AS server
WORKDIR /app

RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /app/bin/server .
COPY --from=builder /app/bin/auditor .
RUN mkdir -p /app/data

# Portas padrão para TCP de clientes e HTTP interno (REST + P2P PBFT)
EXPOSE 8080 8081 8082 8083 9080 9081 9082 9083

ENTRYPOINT ["./server"]

# ==========================================
# ETAPA 3: Imagem do Cliente Motorista
# ==========================================
FROM alpine:latest AS driver-client
WORKDIR /app
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /app/bin/driver-client .
ENTRYPOINT ["./driver-client"]

# ==========================================
# ETAPA 4: Imagem do Cliente Passageiro
# ==========================================
FROM alpine:latest AS passenger-client
WORKDIR /app
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /app/bin/passenger-client .
ENTRYPOINT ["./passenger-client"]

# ==========================================
# ETAPA 5: Imagem do Auditor Independente
# ==========================================
FROM alpine:latest AS auditor
WORKDIR /app
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /app/bin/auditor .
ENTRYPOINT ["./auditor"]
