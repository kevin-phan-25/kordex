{{- define "kordex-dashboard.name" -}}{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}{{- end -}}
{{- define "kordex-dashboard.fullname" -}}{{- if .Values.fullnameOverride }}{{ .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}{{- else }}{{ include "kordex-dashboard.name" . }}{{- end -}}{{- end -}}
{{- define "kordex-dashboard.labels" -}}
app.kubernetes.io/name: {{ include "kordex-dashboard.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}
{{- define "kordex-dashboard.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kordex-dashboard.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
