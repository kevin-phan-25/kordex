{{- define "kordex-control-plane.image" -}}
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
