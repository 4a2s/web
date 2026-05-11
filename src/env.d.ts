/// <reference types="astro/client" />

interface ImportMetaEnv {
  readonly PUBLIC_KEYCLOAK_CLIENT_ID?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}