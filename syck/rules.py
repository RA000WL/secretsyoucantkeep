from __future__ import annotations

import json
import re
from pathlib import Path

from syck.finding import Rule

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

RULES: list[Rule] = [
    # ── Cloud / AWS ──────────────────────────
    Rule("aws_access_key_id",
         "CRITICAL",
         re.compile(r"\b(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b")),
    Rule("aws_cognito_pool_id",
         "MEDIUM",
         re.compile(r"\b(?:us|eu|ap|sa|ca|me|af)-(?:east|west|south|north|central|southeast|northeast)-[0-9]:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")),
    Rule("aws_appsync_key",
         "HIGH",
         re.compile(r"\bda2-[a-z0-9]{26}\b")),
    Rule("aws_secret_access_key",
         "CRITICAL",
         re.compile(r"(?i)aws[_\-\.]?secret[_\-\.]?(?:access[_\-\.]?)?key\s*[:=]\s*['\"]?([A-Za-z0-9+/]{40})['\"]?")),
    Rule("aws_session_token",
         "CRITICAL",
         re.compile(r"(?i)aws[_\-\.]?session[_\-\.]?token\s*[:=]\s*['\"]?[A-Za-z0-9+/=]{16,}['\"]?")),

    # ── GCP ──────────────────────────────────
    Rule("google_api_key",
         "HIGH",
         re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    Rule("google_oauth_token",
         "HIGH",
         re.compile(r"\b[0-9]+-[0-9A-Za-z\_\-]{32}\.apps\.googleusercontent\.com\b")),
    Rule("google_service_account",
         "CRITICAL",
         re.compile(r"\"private_key_id\":\s*\"[a-f0-9]{40}\"")),
    Rule("gcp_service_account_key",
         "CRITICAL",
         re.compile(r"\b-----BEGIN PRIVATE KEY-----\s*\n[ A-Za-z0-9\n+/=]+\s*\n-----END PRIVATE KEY-----\b")),
    Rule("firebase_url",
         "MEDIUM",
         re.compile(r"\bhttps://[a-zA-Z0-9\-]+\.(?:firebaseio\.com|firebasedatabase\.app)\b")),
    Rule("firebase_fcm_key",
         "HIGH",
         re.compile(r"\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}\b")),

    # ── Azure ────────────────────────────────
    Rule("azure_connection_string",
         "CRITICAL",
         re.compile(r"(?i)DefaultEndpointsProtocol=https?;AccountName=[a-z0-9]+;AccountKey=[a-zA-Z0-9+/=]{40,}(?:;EndpointSuffix=core\.windows\.net)?"),
         ),
    Rule("azure_client_id",
         "MEDIUM",
         re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")),
    Rule("azure_client_secret",
         "CRITICAL",
         re.compile(r"(?i)(?:azure|msi)[_-]?(?:client|app)[_-]?(?:secret|key|token|password)\s*[:=]\s*['\"]?([A-Za-z0-9_~.\-=]{34})['\"]?"),
         ),

    # ── GitHub ───────────────────────────────
    Rule("github_personal_access_token",
         "CRITICAL",
         re.compile(r"\bghp_[0-9a-zA-Z]{36}\b")),
    Rule("github_oauth_access_token",
         "CRITICAL",
         re.compile(r"\bgho_[0-9a-zA-Z]{36}\b")),
    Rule("github_app_token",
         "CRITICAL",
         re.compile(r"\b(ghu|ghs|ghr)_[0-9a-zA-Z]{36}\b")),
    Rule("github_refresh_token",
         "CRITICAL",
         re.compile(r"\bghr_[0-9a-zA-Z]{36}\b")),
    Rule("github_fine_grained_token",
         "CRITICAL",
         re.compile(r"github_pat_[0-9a-zA-Z_]{82}\b")),
    Rule("github_old_token",
         "HIGH",
         re.compile(r"\b[0-9a-f]{40}\b")),

    # ── GitLab ───────────────────────────────
    Rule("gitlab_personal_token",
         "CRITICAL",
         re.compile(r"\bglpat-[0-9a-zA-Z\-_]{20,}\b")),
    Rule("gitlab_runner_token",
         "CRITICAL",
         re.compile(r"\bGR1348941[0-9a-zA-Z\-_]{10,}\b")),

    # ── Atlassian / Bitbucket ────────────────
    Rule("bitbucket_client_id",
         "MEDIUM",
         re.compile(r"\b[A-Za-z0-9]{32}\b")),
    Rule("atlassian_api_token",
         "HIGH",
         re.compile(r"\b[3-7][A-Za-z0-9\-_]{42,48}\b")),
    Rule("jira_api_token",
         "HIGH",
         re.compile(r"(?i)(?:atlassian|jira)[_-]?(?:api[_-]?)?token\s*[:=]\s*['\"]?([A-Za-z0-9]{24})['\"]?"),
         ),

    # ── Slack ────────────────────────────────
    Rule("slack_bot_token",
         "CRITICAL",
         re.compile(r"\bxoxb-[0-9A-Za-z\-]{50,200}\b")),
    Rule("slack_webhook_url",
         "HIGH",
         re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),

         ),

    # ── Stripe ───────────────────────────────
    Rule("stripe_publishable_key",
         "MEDIUM",
         re.compile(r"\bpk_(?:test|live)_[0-9a-zA-Z]{24,}\b")),
    Rule("stripe_restricted_key",
         "CRITICAL",
         re.compile(r"\brk_(?:test|live)_[0-9a-zA-Z]{24,}\b")),
    Rule("stripe_secret_key",
         "CRITICAL",
         re.compile(r"\bsk_(?:test|live)_[0-9a-zA-Z]{24,}\b")),
    Rule("stripe_webhook_signing_secret",
         "HIGH",
         re.compile(r"\bwhsec_[0-9a-zA-Z\-_]{24,}\b")),

    # ── Twilio ───────────────────────────────
    Rule("twilio_account_sid",
         "HIGH",
         re.compile(r"\bAC[a-z0-9]{32}\b")),
    Rule("twilio_api_key_sid",
         "HIGH",
         re.compile(r"\bSK[a-z0-9]{32}\b")),
    Rule("twilio_auth_token",
         "CRITICAL",
         re.compile(r"(?i)twilio\s*[:=]\s*['\"]?[a-z0-9]{32}['\"]?"),
         ),

    # ── SendGrid / Mailgun / Mailchimp / Brevo ──
    Rule("sendgrid_api_token",
         "CRITICAL",
         re.compile(r"\bSG\.[A-Za-z0-9_-]{22,26}\.[A-Za-z0-9_-]{43}\b")),
    Rule("mailgun_api_key",
         "HIGH",
         re.compile(r"\bkey-[0-9a-f]{32}\b")),
    Rule("mailchimp_api_key",
         "HIGH",
         re.compile(r"\b[0-9a-f]{32}-us[0-9]{1,2}\b")),
    Rule("brevo_api_key",
         "HIGH",
         re.compile(r"\bxkeys-[0-9a-f]{40}-[a-z0-9]{16}\b")),

    # ── NPM ──────────────────────────────────
    Rule("npm_token",
         "CRITICAL",
         re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),

    # ── API / Dev Tools ──────────────────────
    Rule("heroku_api_key",
         "HIGH",
         re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")),

    # ── Telegram ─────────────────────────────
    Rule("telegram_bot_token",
         "CRITICAL",
         re.compile(r"\b[0-9]{8,10}:[a-zA-Z0-9_-]{35}\b")),

    # ── Discord ──────────────────────────────
    Rule("discord_bot_token",
         "CRITICAL",
         re.compile(r"\b[A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}\b")),
    Rule("discord_webhook_url",
         "HIGH",
         re.compile(r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+"),

         ),

    # ── Heroku ───────────────────────────────
    Rule("heroku_deploy_key",
         "HIGH",
         re.compile(r"\b(?:-----BEGIN RSA PRIVATE KEY-----)\s*[\s\S]{200,}?\s*(?:-----END RSA PRIVATE KEY-----)\b")),

    # ── Shopify ──────────────────────────────
    Rule("shopify_custom_app_token",
         "CRITICAL",
         re.compile(r"\bshpat_[a-fA-F0-9]{32}\b")),
    Rule("shopify_shared_secret",
         "CRITICAL",
         re.compile(r"\bshsec_[a-fA-F0-9]{32}\b")),
    Rule("shopify_access_token",
         "CRITICAL",
         re.compile(r"\bshppa_[a-fA-F0-9]{32}\b")),

    # ── AI Providers ─────────────────────────
    # OpenAI
    Rule("openai_api_key",
         "CRITICAL",
         re.compile(r"\bsk-[a-zA-Z0-9\-_]{20,}\b")),
    Rule("openai_org_key",
         "HIGH",
         re.compile(r"\borg-[a-zA-Z0-9\-_]{20,}\b")),
    Rule("openai_project_key",
         "HIGH",
         re.compile(r"\bproj_[a-zA-Z0-9\-_]{20,}\b")),
    # Anthropic
    Rule("anthropic_api_key",
         "CRITICAL",
         re.compile(r"\bsk-ant-[a-zA-Z0-9\-_]{20,}\b")),
    Rule("anthropic_oauth_token",
         "CRITICAL",
         re.compile(r"\bant-oauth2-[a-zA-Z0-9\-_]{20,}\b")),
    # HuggingFace
    Rule("huggingface_api_token",
         "CRITICAL",
         re.compile(r"\bhf_[a-zA-Z][a-zA-Z0-9]{33}\b")),
    # Replicate
    Rule("replicate_api_token",
         "HIGH",
         re.compile(r"\br8_[0-9a-fA-F]{40,}\b")),
    # Cohere
    Rule("cohere_api_key",
         "HIGH",
         re.compile(r"\b[A-Za-z0-9]{40}\b")),
    # Groq
    Rule("groq_api_key",
         "HIGH",
         re.compile(r"\bgsk_[a-zA-Z0-9]{30,}\b")),
    # Perplexity
    Rule("perplexity_api_key",
         "HIGH",
         re.compile(r"\bpplx-[a-zA-Z0-9\-_]{20,}\b")),
    # xAI/Grok
    Rule("xai_api_key",
         "CRITICAL",
         re.compile(r"\bxai-[a-zA-Z0-9\-_]{20,}\b")),
    # DeepSeek
    Rule("deepseek_api_key",
         "CRITICAL",
         re.compile(r"\bsk-[a-fA-F0-9]{32,}\b")),
    # Fireworks AI
    Rule("fireworks_api_key",
         "HIGH",
         re.compile(r"\bfw_[a-zA-Z0-9]{30,}\b")),
    # OpenRouter
    Rule("openrouter_api_key",
         "HIGH",
         re.compile(r"\bsk-or-[a-zA-Z0-9\-_]{30,}\b")),
    # ElevenLabs
    Rule("elevenlabs_api_key",
         "MEDIUM",
         re.compile(r"\bsk_[a-f0-9]{48}\b")),
    # Cerebras
    Rule("cerebras_api_key",
         "HIGH",
         re.compile(r"\bc-[a-zA-Z0-9]{30,}\b")),
    # NVIDIA
    Rule("nvidia_api_key",
         "MEDIUM",
         re.compile(r"\bnvidia-[a-zA-Z0-9\-_]{20,}\b")),
    # Ollama Cloud
    Rule("ollama_cloud_api_key",
         "MEDIUM",
         re.compile(r"\boll-[a-zA-Z0-9]{30,}\b")),
    # Runway
    Rule("runway_api_key",
         "HIGH",
         re.compile(r"\brw-[a-zA-Z0-9\-_]{30,}\b")),
    # MiniMax
    Rule("minimax_api_key",
         "MEDIUM",
         re.compile(r"\bmm-[a-zA-Z0-9]{30,}\b")),
    # Alibaba Model Studio
    Rule("alibaba_model_studio_api_key",
         "MEDIUM",
         re.compile(r"\bsk-[a-f0-9]{32,}\b")),
    # Moonshot/Kimi
    Rule("moonshot_api_key",
         "MEDIUM",
         re.compile(r"\bms-[a-zA-Z0-9]{30,}\b")),
    # Tencent Cloud
    Rule("tencent_cloud_api_key",
         "MEDIUM",
         re.compile(r"\bAKID[a-zA-Z0-9]{20,}\b")),
    # Vercel AI Gateway
    Rule("vercel_ai_gateway_key",
         "MEDIUM",
         re.compile(r"\bvg-[a-zA-Z0-9]{30,}\b")),
    # Z.AI
    Rule("z_ai_api_key",
         "MEDIUM",
         re.compile(r"\bzai-[a-zA-Z0-9]{30,}\b")),

    # ── Modern SaaS ──────────────────────────
    Rule("supabase_jwt_secret",
         "HIGH",
         re.compile(r"\beyJ[a-z0-9\-_]{30,}\.eyJ[a-z0-9\-_]{30,}\b")),
    Rule("planetscale_password",
         "CRITICAL",
         re.compile(r"\bpscale_pwd_[a-zA-Z0-9\-_]{30,}\b")),
    Rule("linear_api_key",
         "HIGH",
         re.compile(r"\blin_api_[a-zA-Z0-9\-_]{30,}\b")),
    Rule("linear_oauth_token",
         "HIGH",
         re.compile(r"\blin_oauth_[a-zA-Z0-9\-_]{30,}\b")),
    Rule("ngrok_api_key",
         "HIGH",
         re.compile(r"\bngrok_[a-zA-Z0-9\-_]{30,}\b")),
    Rule("cloudflare_api_token",
         "CRITICAL",
         re.compile(r"\b[0-9a-zA-Z\-_]{40,}\b")),
    Rule("cloudflare_origin_ca_key",
         "HIGH",
         re.compile(r"\bv-[0-9a-f]{40,}\b")),
    Rule("doppler_token",
         "HIGH",
         re.compile(r"\bdp\.pt\.[a-zA-Z0-9\-_]{30,}\b")),
    Rule("grafana_api_key",
         "HIGH",
         re.compile(r"\beyJrIjoi[a-zA-Z0-9\-_]{30,}\b")),
    Rule("algolia_api_key",
         "HIGH",
         re.compile(r"\b[0-9a-zA-Z]{32}\b")),
    Rule("vercel_api_token",
         "CRITICAL",
         re.compile(r"\b[a-zA-Z0-9]{24,}\b")),
    Rule("digitalocean_personal_token",
         "HIGH",
         re.compile(r"\bdop_v1_[a-f0-9]{64}\b")),
    Rule("digitalocean_spaces_key",
         "HIGH",
         re.compile(r"\bDO[A-Z0-9]{24}\b")),
    Rule("new_relic_browser_key",
         "MEDIUM",
         re.compile(r"\bNRJS-[a-f0-9]{19}\b")),
    Rule("notion_api_token",
         "HIGH",
         re.compile(r"\bntn_[a-zA-Z0-9\-_]{40,}\b")),
    Rule("instagram_api_token",
         "MEDIUM",
         re.compile(r"\bIGQVJ[A-Za-z0-9\-_]{20,}\b")),

    # ── Observability / DevOps ───────────────
    Rule("datadog_api_key",
         "HIGH",
         re.compile(r"\b[0-9a-f]{32}\b")),
    Rule("datadog_app_key",
         "HIGH",
         re.compile(r"\b[A-Za-z0-9]{40}\b")),
    Rule("sentry_dsn",
         "MEDIUM",
         re.compile(r"https://[0-9a-f]{32}@[a-z0-9]+\.ingest\.sentry\.io/\d+"),
         ),
    Rule("sentry_auth_token",
         "HIGH",
         re.compile(r"\bsntrys_[a-zA-Z0-9\-_]{40,}\b")),
    Rule("pagerduty_api_token",
         "HIGH",
         re.compile(r"\bu\+[a-f0-9]{8}[a-f0-9]{24}\b")),
    Rule("pagerduty_oauth_token",
         "HIGH",
         re.compile(r"\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b")),
    Rule("sumo_logic_access_id",
         "MEDIUM",
         re.compile(r"\bsus[a-zA-Z0-9]{12,}\b")),
    Rule("sumo_logic_access_key",
         "HIGH",
         re.compile(r"\b[a-zA-Z0-9]{64}\b")),

    # ── HashiCorp Vault / Infra ──────────────
    Rule("vault_token",
         "CRITICAL",
         re.compile(r"\bhvs\.[a-zA-Z0-9\-_]{30,}\b")),
    Rule("vault_approle_id",
         "HIGH",
         re.compile(r"\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b")),
    Rule("vault_approle_secret",
         "CRITICAL",
         re.compile(r"\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b")),
    Rule("docker_hub_pat",
         "HIGH",
         re.compile(r"\bdckr_pat_[a-zA-Z0-9\-_]{40,}\b")),
    Rule("kubernetes_secret",
         "HIGH",
         re.compile(r"(?i)apiVersion:\s*v1\s*\nkind:\s*Secret\s*\n")),
    Rule("terraform_api_token",
         "HIGH",
         re.compile(r"\b[a-zA-Z0-9\-_]{40,}\b")),
    Rule("pulumi_access_token",
         "CRITICAL",
         re.compile(r"\bpul-[a-f0-9]{40}\b")),

    # ── Payment / Commerce ───────────────────
    Rule("square_access_token",
         "CRITICAL",
         re.compile(r"\bsq0atp_[0-9a-zA-Z\-_]{22,}\b")),
    Rule("square_sandbox_token",
         "HIGH",
         re.compile(r"\bsq0csp_[0-9a-zA-Z\-_]{22,}\b")),
    Rule("amazon_mws_token",
         "HIGH",
         re.compile(r"\bamzn\.mws\.[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b")),


    # ── Maps / Geo ───────────────────────────
    Rule("google_maps_api_key",
         "HIGH",
         re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    Rule("mapbox_api_token",
         "HIGH",
         re.compile(r"\bsk\.[a-zA-Z0-9]{80,110}\b")),

    # ── Monitoring ───────────────────────────
    Rule("new_relic_api_key",
         "HIGH",
         re.compile(r"\bNRAK-[A-Z0-9]{27}\b")),

    # ── Identity ─────────────────────────────
    Rule("okta_api_token",
         "HIGH",
         re.compile(r"\b[0-9a-zA-Z\-_]{40,}\b")),

    # ── Misc SaaS ────────────────────────────
    Rule("dropbox_api_token",
         "HIGH",
         re.compile(r"\bsl\.[A-Za-z0-9\-_]{130,}\b")),
    Rule("asana_personal_token",
         "HIGH",
         re.compile(r"\b[0-9/]+/[0-9a-f]{32}\b")),

    # ── JWT ──────────────────────────────────
    Rule("jwt_token",
         "HIGH",
         re.compile(r"\beyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\b")),

    # ── Private Keys ─────────────────────────
    Rule("rsa_private_key",
         "CRITICAL",
         re.compile(r"-----BEGIN RSA PRIVATE KEY-----")),
    Rule("dsa_private_key",
         "CRITICAL",
         re.compile(r"-----BEGIN DSA PRIVATE KEY-----")),
    Rule("ec_private_key",
         "CRITICAL",
         re.compile(r"-----BEGIN EC PRIVATE KEY-----")),
    Rule("openssh_private_key",
         "CRITICAL",
         re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----")),
    Rule("pgp_private_key",
         "HIGH",
         re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----")),
    Rule("ssh_private_key",
         "HIGH",
         re.compile(r"\bssh-(?:rsa|dss|ed25519)\s+[A-Za-z0-9+/=]{100,}\b")),

    # ── Database connection strings ──────────
    Rule("postgres_url",
         "CRITICAL",
         re.compile(r"\bpostgres(?:ql)?://[a-zA-Z0-9_]+:[^@\s]+@[a-zA-Z0-9.\-]+:\d+/[a-zA-Z0-9_]+\b")),
    Rule("mysql_url",
         "CRITICAL",
         re.compile(r"\bmysql://[a-zA-Z0-9_]+:[^@\s]+@[a-zA-Z0-9.\-]+:\d+/[a-zA-Z0-9_]+\b")),
    Rule("mongodb_url",
         "CRITICAL",
         re.compile(r"\bmongodb(?:\+srv)?://[a-zA-Z0-9_]+:[^@\s]+@[a-zA-Z0-9.\-]+/\w+\b")),
    Rule("redis_url",
         "CRITICAL",
         re.compile(r"\bredis://[^@\s]+:[^@\s]+@[a-zA-Z0-9.\-]+:\d+\b")),
    Rule("sqlite_url",
         "LOW",
         re.compile(r"\bsqlite[^:]*://[^\s]+")),

    # ── Infrastructure ───────────────────────
    Rule("pypi_api_token",
         "CRITICAL",
         re.compile(r"\bpypi-[A-Za-z0-9\-_]{40,}\b")),
    Rule("rubygems_api_key",
         "HIGH",
         re.compile(r"\brubygems-[a-f0-9]{40}\b")),
    Rule("docker_hub_password",
         "HIGH",
         re.compile(r"\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b")),
    Rule("ansible_vault_password",
         "MEDIUM",
         re.compile(r"(?i)ansible_vault_password\s*[:=]\s*.+")),

    # ── Data / Analytics ─────────────────────
    Rule("segment_api_key",
         "MEDIUM",
         re.compile(r"\b[a-zA-Z0-9-_]{32,}\b")),
    Rule("mixpanel_api_token",
         "MEDIUM",
         re.compile(r"\b[a-f0-9]{32}\b")),

    # ── CRM / Sales ──────────────────────────
    Rule("hubspot_api_key",
         "HIGH",
         re.compile(r"\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b")),

    # ── Monitoring / Observability ───────────
    Rule("elastic_cloud_key",
         "HIGH",
         re.compile(r"\b[a-f0-9]{32}\b")),
    Rule("logz_io_token",
         "HIGH",
         re.compile(r"\b[a-zA-Z0-9]{32,}\b")),
    Rule("papertrail_api_token",
         "HIGH",
         re.compile(r"\b[a-f0-9]{32}\b")),
    Rule("rollbar_access_token",
         "HIGH",
         re.compile(r"\b[a-f0-9]{32}\b")),

    # ── Productivity / Design ────────────────
    Rule("figma_api_token",
         "HIGH",
         re.compile(r"\bfigd_[a-zA-Z0-9\-_]{20,}\b")),
    Rule("notion_integration_token",
         "HIGH",
         re.compile(r"\bsecret_[a-zA-Z0-9]{43}\b")),

    # ── Social Media ─────────────────────────
    Rule("twitter_api_key",
         "MEDIUM",
         re.compile(r"\b[a-zA-Z0-9]{25}\b")),
    Rule("twitter_api_secret",
         "CRITICAL",
         re.compile(r"\b[a-zA-Z0-9]{50}\b")),

    # ── CI/CD ────────────────────────────────
    Rule("circleci_token",
         "HIGH",
         re.compile(r"\b[a-f0-9]{40}\b")),

    # ── Hosting / CDN ────────────────────────
    Rule("netlify_api_token",
         "HIGH",
         re.compile(r"\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b")),

    # ── Cloud (non-AWS) ──────────────────────
    Rule("oracle_cloud_ocid",
         "MEDIUM",
         re.compile(r"\bocid1\.[a-z0-9]+\.[a-z0-9]+\.\.\.\b")),

    # ── Payment / Fintech ────────────────────
    Rule("paypal_braintree_token",
         "CRITICAL",
         re.compile(r"\baccess_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}\b")),
    Rule("recurly_api_key",
         "HIGH",
         re.compile(r"\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b")),
    Rule("razorpay_api_key",
         "HIGH",
         re.compile(r"\brzp_(?:test|live)_[A-Za-z0-9]{14,}\b")),

    # ── Media / CDN ──────────────────────────
    Rule("cloudinary_api_key",
         "MEDIUM",
         re.compile(r"\b[0-9]{6,15}\b")),

    # ── Push Notifications ───────────────────
    Rule("onesignal_api_key",
         "HIGH",
         re.compile(r"\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b")),

    # ── LaunchDarkly ─────────────────────────
    Rule("launchdarkly_api_key",
         "HIGH",
         re.compile(r"\bsdk-[a-f0-9]{32}\b")),
    Rule("launchdarkly_access_token",
         "HIGH",
         re.compile(r"\bapi-[a-f0-9]{32}\b")),

    # ── Elastic Cloud ────────────────────────
    Rule("elasticsearch_cloud_id",
         "LOW",
         re.compile(r"\b[a-zA-Z0-9\-_]{40,}:[a-zA-Z0-9\-_]{10,}\b")),

    # ── Mixpanel ─────────────────────────────
    Rule("mixpanel_service_token",
         "HIGH",
         re.compile(r"\b[a-f0-9]{32}\b")),

    # ── Segment ──────────────────────────────
    Rule("segment_write_key",
         "HIGH",
         re.compile(r"\b[a-zA-Z0-9-_]{32,}\b")),

    # ── CI/CD secrets ────────────────────────
    Rule("jenkins_api_token",
         "HIGH",
         re.compile(r"\b[a-f0-9]{32}\b")),
    Rule("travis_ci_api_token",
         "HIGH",
         re.compile(r"\b[a-zA-Z0-9\-_]{22,}\b")),

    # ── SPA embedded config ──────────────────
    Rule("firebase_config",
         "MEDIUM",
         re.compile(r"apiKey:\s*['\"][A-Za-z0-9]{30,}['\"]")),
    Rule("aws_cognito_config",
         "LOW",
         re.compile(r"UserPoolId:\s*['\"][a-zA-Z0-9_]+['\"]")),

    # ── Generic patterns ─────────────────────
    Rule("generic_secret",
         "HIGH",
         re.compile(r"(?i)(?:secret|password|passwd|pwd|token|api[_-]?key|access[_-]?key|auth[_-]?token|private[_-]?key)\s*[:=]\s*['\"]?([A-Za-z0-9_\-+!@#$%^&*()=]{20,})['\"]?"),
         ),
    Rule("dotenv_secret",
         "HIGH",
         re.compile(r"(?i)^\s*(?:export\s+)?(?:SECRET|TOKEN|API_KEY|PASSWORD|PASSWD|PRIVATE_KEY|ACCESS_KEY)\s*=\s*['\"]?([A-Za-z0-9_\-+!@#$%^&*()=]{20,})['\"]?\s*$"),
         ),
    Rule("basic_auth_header",
         "HIGH",
         re.compile(r"\b(?:Basic|Bearer)\s+[A-Za-z0-9\-_+/=]{20,}\b")),
    Rule("wakatime_api_key",
         "MEDIUM",
         re.compile(r"\bwaka_[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b")),
    Rule("airtable_api_key",
         "HIGH",
         re.compile(r"\bkey[A-Za-z0-9]{14,}\b")),
    Rule("recaptcha_key",
         "MEDIUM",
         re.compile(r"\b6L[eLd][A-Za-z0-9\-_]{30,}\b")),
    Rule("credential_url",
         "HIGH",
         re.compile(r"\bhttps?://[^\s:@]+:[^\s:@]+@[^\s]{3,}\b")),

    # ── GitLab Runner ────────────────────────
    Rule("gitlab_runner_registration_token",
         "CRITICAL",
         re.compile(r"\bGR1348941[A-Za-z0-9\-_]{10,}\b")),

    # ── Slack App Token ──────────────────────
    Rule("slack_app_level_token",
         "CRITICAL",
         re.compile(r"\bxapp-[0-9A-Za-z\-]{50,200}\b")),

    # ── Shopify Custom App Token ─────────────
    Rule("shopify_custom_app_token_v2",
         "CRITICAL",
         re.compile(r"\bshpat_[a-fA-F0-9]{32}\b")),

    # ── New Relic Browser Key ────────────────
    Rule("new_relic_browser_key_v2",
         "MEDIUM",
         re.compile(r"\bNRJS-[a-f0-9]{19}\b")),

    # ── Notion ───────────────────────────────
    Rule("notion_api_token_v2",
         "HIGH",
         re.compile(r"\bntn_[a-zA-Z0-9\-_]{40,}\b")),

    # ── Instagram ────────────────────────────
    Rule("instagram_api_token_v2",
         "MEDIUM",
         re.compile(r"\bIGQVJ[A-Za-z0-9\-_]{20,}\b")),

    # ── DigitalOcean Spaces Key ──────────────
    Rule("digitalocean_spaces_key_v2",
         "HIGH",
         re.compile(r"\bDO[A-Z0-9]{24}\b")),

    # ── Doppler ──────────────────────────────
    Rule("doppler_token_v2",
         "HIGH",
         re.compile(r"\bdp\.pt\.[a-zA-Z0-9\-_]{30,}\b")),

    # ── Grafana ──────────────────────────────
    Rule("grafana_api_key_v2",
         "HIGH",
         re.compile(r"\beyJrIjoi[a-zA-Z0-9\-_]{30,}\b")),

    # ── Algolia ──────────────────────────────
    Rule("algolia_api_key_v2",
         "HIGH",
         re.compile(r"\b[0-9a-zA-Z]{32}\b")),

    # ── reCAPTCHA ────────────────────────────
    Rule("recaptcha_key_v2",
         "MEDIUM",
         re.compile(r"\b6L[eLd][A-Za-z0-9\-_]{30,}\b")),

    # ── Amazon MWS ───────────────────────────
    Rule("amazon_mws_token_v2",
         "HIGH",
         re.compile(r"\bamzn\.mws\.[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b")),

    # ── PayPal Braintree ─────────────────────
    Rule("paypal_braintree_token_v2",
         "CRITICAL",
         re.compile(r"\baccess_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}\b")),

    # ── Azure Client Secret ──────────────────
    Rule("azure_client_secret_v2",
         "CRITICAL",
         re.compile(r"(?i)(?:azure|msi)[_-]?(?:client|app)[_-]?(?:secret|key|token|password)\s*[:=]\s*['\"]?([A-Za-z0-9_~.\-=]{34})['\"]?"),
         ),

    # ── API Key Header ───────────────────────
    Rule("api_key_header",
         "HIGH",
         re.compile(r"(?i)(?:x-)?api-?key\s*:\s*['\"]([A-Za-z0-9_\-+!@#$%^&*()=]{20,})['\"]"),
         ),

    # ── Credential URL ───────────────────────
    Rule("credential_url_v2",
         "HIGH",
         re.compile(r"\bhttps?://[^\s:@]+:[^\s:@]+@[^\s]{3,}\b")),

]

_RULE_RANK: dict[str, int] = {r.name: SEVERITY_ORDER[r.severity] for r in RULES}
_MIN_RANK: int = SEVERITY_ORDER["LOW"]


def load_custom_rules(path: str) -> list[Rule]:
    with open(path) as f:
        data = json.load(f)
    rules = []
    for item in data:
        rules.append(Rule(
            name=item["name"],
            severity=item["severity"],
            pattern=re.compile(item["pattern"]),
        ))
    return rules
