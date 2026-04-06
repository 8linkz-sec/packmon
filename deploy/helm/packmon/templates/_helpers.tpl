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
  {{- required "postgresql.password is required when postgresql.enabled=true. Set a strong password in your values override." .Values.postgresql.password -}}
{{- else -}}
  {{- required "externalDatabase.password is required when postgresql.enabled=false." .Values.externalDatabase.password -}}
{{- end -}}
{{- end -}}
