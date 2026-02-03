FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod .
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /bin/entitlements ./

FROM alpine:3.19
RUN adduser -D -H -u 10001 app
USER 10001
COPY --from=build /bin/entitlements /bin/entitlements
EXPOSE 8083
ENTRYPOINT ["/bin/entitlements"]
