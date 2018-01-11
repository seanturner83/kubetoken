FROM golang:1.8 as builder
RUN mkdir -p /go/src/github.com/atlassian/kubetoken
COPY . /go/src/github.com/atlassian/kubetoken/.
WORKDIR /go/src/github.com/atlassian/kubetoken
RUN go get ./...
ARG KUBETOKEND_HOST=http://localhost:8080
ARG LDAP_SEARCH_BASE=dc=office,dc=loro,dc=swiss
RUN go build -x
RUN go build -x -ldflags="-X github.com/atlassian/kubetoken.Version=1234 -X github.com/atlassian/kubetoken.SearchBase=$LDAP_SEARCH_BASE -X github.com/atlassian/kubetokend.SearchBase=$LDAP_SEARCH_BASE -X github.com/atlassian/kubetoken.BindDN=$BIND_DN -X main.BindDN=$BIND_DN" ./cmd/kubetokend
RUN go build -x -ldflags="-X github.com/atlassian/kubetoken.Version=1234 -X main.kubetokend=$KUBETOKEND_HOST -X github.com/atlassian/kubetoken.SearchBase=$LDAP_SEARCH_BASE -X github.com/atlassian/kubetokend.SearchBase=$LDAP_SEARCH_BASE" ./cmd/kubetoken

FROM ubuntu:16.04
RUN apt-get update && apt-get install ca-certificates -y
RUN update-ca-certificates
COPY --from=builder /go/src/github.com/atlassian/kubetoken/kubetokend /bin/kubetokend
COPY --from=builder /go/src/github.com/atlassian/kubetoken/kubetoken /bin/kubetoken
ENV PORT=8080
EXPOSE $PORT
ENV LDAP_HOST=localhost
ENTRYPOINT /bin/kubetokend --ldap $LDAP_HOST

