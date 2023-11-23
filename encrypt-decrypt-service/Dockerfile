FROM golang:latest as dependencies

WORKDIR /app

COPY go.mod .
COPY go.sum .

RUN go mod download


FROM dependencies as build

COPY . .

RUN go test ./...

RUN go build -o encrypt-decrypt-service


FROM golang:latest

WORKDIR /app

COPY --from=build /app/encrypt-decrypt-service /app/

EXPOSE 8080

CMD ["./encrypt-decrypt-service"]

