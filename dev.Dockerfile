FROM 117503445/dev-golang

# RUN go install github.com/goreleaser/goreleaser/v2@latest
# RUN pacman -Sy npm --noconfirm && npm install @serverless-devs/s -g
RUN pacman -Sy skopeo --noconfirm