{{/*
Expand the name of the chart.
*/}}
{{- define "separ.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "separ.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "separ.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "separ.labels" -}}
helm.sh/chart: {{ include "separ.chart" . }}
{{ include "separ.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "separ.selectorLabels" -}}
app.kubernetes.io/name: {{ include "separ.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "separ.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "separ.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
PostgreSQL connection string
*/}}
{{- define "separ.postgresqlUrl" -}}
{{- if .Values.postgresql.enabled }}
postgres://{{ .Values.postgresql.auth.username }}:{{ .Values.postgresql.auth.password }}@{{ .Release.Name }}-postgresql:5432/{{ .Values.postgresql.auth.database }}
{{- else }}
{{- .Values.externalDatabase.url }}
{{- end }}
{{- end }}

{{/*
SpiceDB PostgreSQL connection string
*/}}
{{- define "separ.spicedbPostgresqlUrl" -}}
{{- if .Values.postgresql.enabled }}
postgres://{{ .Values.postgresql.auth.username }}:{{ .Values.postgresql.auth.password }}@{{ .Release.Name }}-postgresql:5432/spicedb?sslmode=disable
{{- else }}
{{- .Values.spicedb.config.datastoreConnUri }}
{{- end }}
{{- end }}

{{/*
SpiceDB endpoint
*/}}
{{- define "separ.spicedbEndpoint" -}}
{{- if .Values.spicedb.enabled }}
{{ include "separ.fullname" . }}-spicedb:{{ .Values.spicedb.service.grpcPort }}
{{- else }}
{{- .Values.externalSpicedb.endpoint }}
{{- end }}
{{- end }}

