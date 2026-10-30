# CreatorStudio AI

CreatorStudio AI is a self-hosted workspace for organizing video projects, preparing clips, and publishing content. It runs on Node.js and Express, stores accounts, projects, and media metadata in PostgreSQL, and can keep uploaded media on a persistent disk.

## Features

- Email and password accounts with PostgreSQL-backed sessions.
- Create, search, rename, describe, and delete projects.
- Upload and preview video and audio, with upload progress and saved asset metadata.
- Set clip trim points and render downloadable MP4 clips with FFmpeg.
- Optional AI-assisted titles, descriptions, captions, tags, and editing plans. Basic drafting remains available without an OpenAI key.
- Connect YouTube and upload a project video.
- Connect an eligible Instagram professional account and publish a Reel through the Instagram Graph API.
- Render Blueprint for the web service, PostgreSQL database, persistent media disk, and environment configuration.

## Requirements

- Node.js 20 or later
- PostgreSQL
- FFmpeg support for clip rendering (the project includes `ffmpeg-static`)

## Run locally

1. Copy `.env.example` to `.env`.
2. Set `DATABASE_URL`, `SESSION_SECRET`, and `TOKEN_ENCRYPTION_KEY` in `.env`.
3. Install dependencies and start the server:

   ```bash
   npm install
   npm start
   ```

4. Open [http://localhost:3000](http://localhost:3000). The first registered account can sign in after signup. Database and session tables are initialized on startup.

To run with automatic Node.js restarts during development:

```bash
npm run dev
```

Generate a 32-byte base64 token encryption key with:

```bash
node -e "console.log(require('node:crypto').randomBytes(32).toString('base64'))"
```

## Deploy to Render

1. Push the project to a GitHub repository.
2. In Render, create a new Blueprint and select the repository. Render reads `render.yaml` to configure the Node service, PostgreSQL database, and persistent media disk.
3. Set `APP_URL` to the deployed HTTPS address. Add the provider credentials you plan to use, then deploy.

The Blueprint uses a disk-capable paid web service because uploaded media needs persistent storage. For a temporary preview without a disk, set `UPLOAD_DIR=./uploads`; files on an ephemeral filesystem may be lost when the service is redeployed or restarted. Keep `UPLOAD_DIR` inside the configured disk mount for persistent uploads.

## Optional integrations

### YouTube

Create a Google Cloud project, enable YouTube Data API v3, and create a Web OAuth client. Add this authorized redirect URI, replacing the hostname with your deployed app's URL:

```text
https://YOUR-APP.onrender.com/api/oauth/youtube/callback
```

Set `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, and `GOOGLE_REDIRECT_URI`. OAuth consent-screen rules and YouTube API quotas apply. Upload visibility defaults to private.

### Instagram Reels

Configure a Meta app for Instagram Graph API publishing. Connect an Instagram Creator or Business account to a Facebook Page and grant the permissions required by Meta, including `instagram_basic`, `instagram_content_publish`, `pages_show_list`, and `pages_read_engagement` where applicable.

Set `META_APP_ID`, `META_APP_SECRET`, and `META_REDIRECT_URI` to use this callback URL:

```text
https://YOUR-APP.onrender.com/api/oauth/instagram/callback
```

The app must be reachable over HTTPS so Instagram can fetch media during publishing. Meta may require app review or an eligible app mode before external accounts can use the integration.

### AI suggestions

Set `OPENAI_API_KEY` to enable generated metadata suggestions. `OPENAI_MODEL` is optional and defaults to `gpt-4o-mini`. The app's basic drafting helper works without an API key.

## Environment configuration

Use `.env.example` as the configuration template for local development. In production, set environment variables in Render rather than committing a `.env` file.

Important settings:

| Variable | Purpose |
| --- | --- |
| `DATABASE_URL` | PostgreSQL connection string |
| `SESSION_SECRET` | Secret used to sign sessions |
| `TOKEN_ENCRYPTION_KEY` | Base64-encoded 32-byte key for encrypting social tokens at rest |
| `APP_URL` | Public base URL used for OAuth and publishing |
| `UPLOAD_DIR` | Directory for uploaded media; use a persistent disk in production |
| `MAX_UPLOAD_MB` | Maximum upload size in megabytes |
| `OPENAI_API_KEY` | Optional key for AI suggestions |
| `GOOGLE_*` | Optional YouTube OAuth configuration |
| `META_*` | Optional Instagram/Meta configuration |

Keep `TOKEN_ENCRYPTION_KEY` unchanged across deployments. Changing it prevents the app from decrypting previously saved social connections. Back up PostgreSQL and persistent media together.

## Security and limitations

- Passwords are hashed with bcrypt; session cookies use HTTP-only settings and secure cookies in production.
- Social OAuth tokens are encrypted in PostgreSQL.
- OAuth state is signed, and project and media access is scoped to the signed-in account.
- Upload size and file-type checks are applied.
- Configure provider consent, HTTPS, and account access policies before public use.
- This starter does not currently include email verification, password reset, team collaboration, or administrator account recovery.
- The app does not generate dubbed voices or lip-synced video.

## API overview

- `/api/auth/*` — account registration and sign-in
- `/api/projects` — project management
- `/api/assets` — media upload and asset management
- `/api/ai/metadata` — optional metadata suggestions
- `/api/oauth/youtube/start` and `/api/oauth/instagram/start` — connect publishing accounts
- `/api/publish/youtube` and `/api/publish/instagram` — publish a selected project video
- `/health` — service and database health check

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
