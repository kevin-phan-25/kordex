{{- define "kordex-agent.name" -}}
{{- printf "%s-agent" .Release.Name | trunc 50 | trimSuffix "-" -}}
{{- end -}}
{{- define "kordex-agent.clusterRole" -}}
{{- printf "%s-%s" (include "kordex-agent.name" .) (printf "%s/%s" .Release.Namespace .Release.Name | sha256sum | trunc 10) -}}
{{- end -}}
