FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod .
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /bin/payment ./

FROM alpine:3.19
RUN adduser -D -H -u 10001 app
USER 10001
COPY --from=build /bin/payment /bin/payment
EXPOSE 8081
ENTRYPOINT ["/bin/payment"]
