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
{{- define "kordex-dashboard.image" -}}
{{- $repository := required "image.repository must be set" .Values.image.repository -}}
{{- if and .Values.image.requireDigest (not .Values.image.digest) -}}
{{- fail "image.digest is required when image.requireDigest is true; supply an immutable sha256 digest" -}}
{{- end -}}
{{- if .Values.image.digest -}}
{{- if not (regexMatch "^sha256:[a-f0-9]{64}$" .Values.image.digest) -}}
{{- fail "image.digest must be sha256: followed by 64 lowercase hexadecimal characters" -}}
{{- end -}}
{{- if not (regexMatch "^[a-z0-9.-]+(:[0-9]+)?(/[a-z0-9._-]+)+$" $repository) -}}
{{- fail "image.repository must be an untagged lowercase OCI repository when image.digest is set" -}}
{{- end -}}
{{- printf "%s@%s" $repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" $repository .Values.image.tag -}}
{{- end -}}
{{- end -}}
