{{- define "kordex-operator.name" -}}
{{- printf "%s-operator" .Release.Name | trunc 50 | trimSuffix "-" -}}
{{- end -}}
{{- define "kordex-operator.clusterRole" -}}
{{- printf "%s-%s" (include "kordex-operator.name" .) (printf "%s/%s" .Release.Namespace .Release.Name | sha256sum | trunc 10) -}}
{{- end -}}
