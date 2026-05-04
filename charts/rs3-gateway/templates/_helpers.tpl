{{- define "rs3-gateway.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "rs3-gateway.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "rs3-gateway.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "rs3-gateway.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ include "rs3-gateway.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "rs3-gateway.selectorLabels" -}}
app.kubernetes.io/name: {{ include "rs3-gateway.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "rs3-gateway.secretName" -}}
{{- if .Values.credentials.existingSecret -}}
{{- .Values.credentials.existingSecret -}}
{{- else -}}
{{- include "rs3-gateway.fullname" . -}}
{{- end -}}
{{- end -}}

{{- define "rs3-gateway.validateValues" -}}
{{- if not .Values.repository.id -}}
{{- fail "repository.id is required; use a stable value for key derivation" -}}
{{- end -}}
{{- if and (ne .Values.anchor.mode "memory") (ne .Values.anchor.mode "kubernetes-lease") -}}
{{- fail "anchor.mode must be memory or kubernetes-lease" -}}
{{- end -}}
{{- if and (eq .Values.anchor.mode "memory") (not .Values.anchor.allowMemory) -}}
{{- fail "anchor.mode=memory requires anchor.allowMemory=true; use kubernetes-lease for durable rollback protection" -}}
{{- end -}}
{{- end -}}

{{- define "rs3-gateway.repositoryKeySecretName" -}}
{{- if .Values.repositoryKeys.existingSecret -}}
{{- .Values.repositoryKeys.existingSecret -}}
{{- else -}}
{{- printf "%s-repository-keys" (include "rs3-gateway.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "rs3-gateway.serviceAccountName" -}}
{{- if .Values.serviceAccount.name -}}
{{- .Values.serviceAccount.name -}}
{{- else -}}
{{- include "rs3-gateway.fullname" . -}}
{{- end -}}
{{- end -}}
