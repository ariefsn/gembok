# Gembok

Gembok is a microservice for authentication. Built on top of `Go`, `Redis`, and `MongoDB`.

## Features

1. [RestAPI](#restapi) ✅
2. [GraphQL](#graphql) 🛠️
3. [Notification](#notification-via-terkirim) ✅
4. [Templates](#templates)
5. [OAuth](#oauth) 🛠️
6. [Docker](#docker) 🛠️

### RestAPI

> Communication through RestAPI with Swagger documentation. For those who use Open API Generator, this will be an advantage.

### GraphQL

> WIP 🛠️

### Notification (via [Terkirim](https://terkirim.cloud))

> Notification will be sent via [Terkirim](https://terkirim.cloud) for easy integration. It supports Whatsapp web API, and for email, it can send `HTML` or `MJML` format 🎉. For more info please check the original website [https://terkirim.cloud](https://terkirim.cloud).

### Templates

> For notification email, the templates are customizable, with the power of `MJML` (if uses Terkirim), it will be easier to handle multiple email clients, responsiveness, or even for light/dark mode 🎉. To customize, we can create a template `HTML`/`MJML` inside the `templates` directory, and then edit the values of the `config.json`.

### OAuth

> WIP 🛠️

### Docker

> WIP 🛠️
