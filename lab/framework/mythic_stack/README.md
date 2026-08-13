# Mythic lab stack

The Mythic scenario needs the real Mythic server stack running on the host
(the scenario container runs the built agent against it over host networking).

## Manual bring-up (one-time, ~15 min first time)

```bash
cd /tmp/tools_tmp/mythic          # Mythic repo + mythic-cli (built locally)
./mythic-cli config set MYTHIC_ADMIN_PASSWORD "Password123!"
docker compose up -d mythic_postgres mythic_rabbitmq mythic_server
# fix port conflicts / certs as needed (see notes below), then:
docker compose up -d mythic_graphql mythic_react mythic_nginx mythic_documentation mythic_jupyter
./mythic-cli install folder /tmp/tools_tmp/mythic-c2-http   # http c2 profile
docker compose up -d http
# athena payload type (host network, RABBITMQ creds from mythic_rabbitmq):
docker run -d --name athena --network host -v "$PWD/InstalledServices/athena:/Mythic/" \
  -e MYTHIC_ADDRESS=http://127.0.0.1:17443/agent_message \
  -e RABBITMQ_USER=mythic_user -e RABBITMQ_PASSWORD=<from container env> \
  -e RABBITMQ_HOST=127.0.0.1 -e RABBITMQ_PORT=5672 -e RABBITMQ_VHOST=mythic_vhost \
  -e MYTHIC_SERVER_HOST=127.0.0.1 -e MYTHIC_SERVER_PORT=17443 ghcr.io/mythicagents/athena:v2.2.4
```

Then create a Linux arm64 Athena payload (callback_host http://127.0.0.1,
callback_port 80) and copy the built binary into
`/tmp/behinder_lab/tools/mythic/athena_agent` (+ libMono.Unix.so).

## Notes

- The release source ships obfuscated names; core images are
  `ghcr.io/its-a-feature/mythic_*:v3.4.0.61`.
- Port conflicts (8080/3000/8888/7443) were remapped in `.env` for this host.
- nginx needs `nginx-docker/ssl/mythic-cert.{crt,key}` + `mythic-ssl.{crt,key}`.
- The agent needs `libicu` at runtime (or DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1
  if the runtimeconfig allows it).
