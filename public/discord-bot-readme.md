# Secrovia Discord API Bot Guide

## What the bot does

Your Discord bot receives a custom command and a Lua source file or source link. It reads the source, sends it to the selected Secrovia API endpoint, waits for the response, and sends the processed code back to the Discord channel.

## Setup

1. Create a Discord application and bot in the Discord Developer Portal.
2. Invite the bot to your server with permission to read messages, attach files, and send messages.
3. Create an API token in the Secrovia dashboard for the API service you want to use.
4. Store the API token in an environment variable. Never commit it to source control or expose it in a public message.
5. Register any command name you prefer, such as `.obf`, `.debug`, `.normal`, `.maximum`, or `.god`.

## Command flow

The command name is controlled by your bot code. The Secrovia API does not automatically create or detect Discord commands.

When a user sends a command, your bot should:

1. Check that the message contains a file attachment or a supported source link.
2. Download or read the source text.
3. Send a JSON POST request to the selected API endpoint.
4. Include `Authorization: Bearer YOUR_API_TOKEN` and the source code in the request body.
5. Wait for the API response and send the output back to Discord as a file or code block.

## Example request

```bash
curl -X POST https://secrovia.vercel.app/api/v1/obfuscator \
  -H "Authorization: Bearer $SECROVIA_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"code":"print(\\"hello\\")","level":"debug"}'
```

## Security

Validate file size and file type before downloading source files. Set a request timeout, handle API errors, and keep the API token server-side. Do not place the token in client-side JavaScript or return it in Discord responses.
