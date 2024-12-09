FROM golang:1.23

WORKDIR /app

COPY . .

RUN go mod tidy && go build -o bin/cercle main.go && go test -v ./...

CMD ["/app/bin/cercle"]