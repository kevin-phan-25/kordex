{{- define "kordex-agent-relay.name" -}}
{{- printf "%s-agent-relay" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- define "kordex-agent-relay.image" -}}
{{- $repository := required "image.repository must be set" .Values.image.repository -}}
{{- $digest := required "image.digest must be a reviewed immutable sha256 digest" .Values.image.digest -}}
{{- if not (regexMatch "^sha256:[a-f0-9]{64}$" $digest) -}}{{ fail "image.digest must be sha256: followed by 64 lowercase hexadecimal characters" }}{{- end -}}
{{- if not (regexMatch "^[a-z0-9.-]+(:[0-9]+)?(/[a-z0-9._-]+)+$" $repository) -}}{{ fail "image.repository must be an untagged lowercase OCI repository" }}{{- end -}}
{{- printf "%s@%s" $repository $digest -}}
{{- end -}}
