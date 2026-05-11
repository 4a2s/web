/// <reference types="astro/client" />

declare global {
  namespace App {
    interface Locals {
      session?: import('./lib/keycloak-server').StoredKeycloakSession | null;
    }
  }
}

interface ImportMetaEnv {
  readonly KEYCLOAK_ISSUER?: string;
  readonly KEYCLOAK_CLIENT_ID?: string;
  readonly KEYCLOAK_CLIENT_SECRET?: string;
  readonly KEYCLOAK_COOKIE_SECRET?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}

export {};