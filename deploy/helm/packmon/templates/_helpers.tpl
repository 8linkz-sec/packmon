{{- define "packmon.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "packmon.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "packmon.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "packmon.labels" -}}
app.kubernetes.io/name: {{ include "packmon.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | quote }}
{{- end -}}

{{/*
Validate that a PostgreSQL password is set when the built-in PostgreSQL is
enabled, or that an external database password is set otherwise.
*/}}
{{- define "packmon.validateDBPassword" -}}
{{- if .Values.postgresql.enabled -}}
  {{- $password := required "postgresql.password is required when postgresql.enabled=true. Set a strong password in your values override." .Values.postgresql.password -}}
{{- else -}}
  {{- $password := required "externalDatabase.password is required when postgresql.enabled=false." .Values.externalDatabase.password -}}
{{- end -}}
{{- end -}}

{{/*
Validate that the feed-key encryption secret is explicitly configured.
*/}}
{{- define "packmon.validateEncryptionKey" -}}
{{- $key := required "server.encryptionKey is required. Set a strong encryption key for stored feed API keys." .Values.server.encryptionKey -}}
{{- end -}}

{{/*
Validate that production deployments are configured with a transport-security
mode that Packmon will accept at startup.
*/}}
{{- define "packmon.validateTransportSecurity" -}}
{{- if eq .Values.server.mode "production" -}}
  {{- $tlsEnabled := and .Values.server.tls.certFile .Values.server.tls.keyFile -}}
  {{- $proxyEnabled := gt (len .Values.server.trustedProxies) 0 -}}
  {{- $localHTTP := .Values.server.allowInsecureLocalHTTP -}}
  {{- if not (or $tlsEnabled $proxyEnabled $localHTTP) -}}
    {{- fail "production server requires transport security: set server.tls.certFile/keyFile for in-app TLS, server.trustedProxies for a TLS-terminating proxy, or server.allowInsecureLocalHTTP=true for loopback-only local deployments." -}}
  {{- end -}}
  {{- if and $localHTTP (ne (.Values.server.publicHost | trim) "localhost") (ne (.Values.server.publicHost | trim) "127.0.0.1") (ne (.Values.server.publicHost | trim) "::1") -}}
    {{- fail "server.allowInsecureLocalHTTP=true is only valid with server.publicHost localhost, 127.0.0.1, or ::1." -}}
  {{- end -}}
{{- end -}}
{{- end -}}

{{/*
Validate that the one-time admin bootstrap password is explicitly configured and
is not the documented placeholder value.
*/}}
{{- define "packmon.validateAdminPassword" -}}
{{- $password := required "admin.initialPassword is required. Set a strong one-time bootstrap password in your values override." .Values.admin.initialPassword -}}
{{- if eq ($password | trim) "change-me" -}}
  {{- fail "admin.initialPassword must not be the placeholder value \"change-me\"." -}}
{{- end -}}
{{- end -}}
