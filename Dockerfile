##
## STEP 1 - BUILD
##

# specify the base image to  be used for the application, alpine or ubuntu
FROM golang:1.23-alpine AS build

ARG PORT

ENV PORT $PORT

# create a working directory inside the image
WORKDIR /app

# copy Go modules and dependencies to image
COPY . .

# download Go modules and dependencies
RUN go mod tidy

EXPOSE ${PORT}

# compile application
RUN go build -o /binary

##
## STEP 2 - DEPLOY
##
FROM scratch

WORKDIR /

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /binary /binary

COPY --from=build /app/templates /templates
COPY --from=build /app/docs /docs

ENTRYPOINT ["/binary"]