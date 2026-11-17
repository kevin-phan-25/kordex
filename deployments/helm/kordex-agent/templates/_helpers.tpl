{{- define "kordex-agent.name" -}}
{{- printf "%s-agent" .Release.Name | trunc 50 | trimSuffix "-" -}}
{{- end -}}
{{- define "kordex-agent.clusterRole" -}}
{{- printf "%s-%s" (include "kordex-agent.name" .) (printf "%s/%s" .Release.Namespace .Release.Name | sha256sum | trunc 10) -}}
{{- end -}}
{{- define "kordex-agent.image" -}}
{{- $repository := required "image.repository must be set" .Values.image.repository -}}
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
