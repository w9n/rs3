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

{{- define "rs3-gateway.adminTokenSecretName" -}}
{{- if .Values.admin.existingTokenSecret -}}
{{- .Values.admin.existingTokenSecret -}}
{{- else -}}
{{- printf "%s-admin" (include "rs3-gateway.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "rs3-gateway.validateValues" -}}
{{- if not .Values.repository.id -}}
{{- fail "repository.id is required; use a stable value for keyring envelope binding" -}}
{{- end -}}
{{- if ne .Values.repository.format "v2-preview" -}}
{{- fail "repository.format must be v2-preview" -}}
{{- end -}}
{{- if and (ne .Values.anchor.mode "memory") (ne .Values.anchor.mode "kubernetes-lease") -}}
{{- fail "anchor.mode must be memory or kubernetes-lease" -}}
{{- end -}}
{{- if and (eq .Values.anchor.mode "memory") (not .Values.anchor.allowMemory) -}}
{{- fail "anchor.mode=memory requires anchor.allowMemory=true; use kubernetes-lease for durable rollback protection" -}}
{{- end -}}
{{- if eq .Values.anchor.mode "kubernetes-lease" -}}
{{- if not .Values.anchor.name -}}
{{- fail "anchor.name is required when anchor.mode=kubernetes-lease" -}}
{{- end -}}
{{- if and (not .Values.serviceAccount.create) (not .Values.serviceAccount.name) -}}
{{- fail "serviceAccount.name is required when serviceAccount.create=false and anchor.mode=kubernetes-lease" -}}
{{- end -}}
{{- if and (not .Values.rbac.create) (not .Values.rbac.existing) -}}
{{- fail "rbac.create=false requires rbac.existing=true when anchor.mode=kubernetes-lease" -}}
{{- end -}}
{{- end -}}
{{- if and .Values.repository.retention.mode (and (ne .Values.repository.retention.mode "governance") (ne .Values.repository.retention.mode "compliance")) -}}
{{- fail "repository.retention.mode must be empty, governance, or compliance" -}}
{{- end -}}
{{- if and (ne .Values.gateway.mode "read-write") (ne .Values.gateway.mode "restore-readonly") -}}
{{- fail "gateway.mode must be read-write or restore-readonly" -}}
{{- end -}}
{{- if and (ne .Values.gateway.writerGuard "required") (ne .Values.gateway.writerGuard "off") -}}
{{- fail "gateway.writerGuard must be required or off" -}}
{{- end -}}
{{- if and (eq .Values.gateway.writerGuard "required") (ne .Values.anchor.mode "kubernetes-lease") -}}
{{- fail "gateway.writerGuard=required requires anchor.mode=kubernetes-lease" -}}
{{- end -}}
{{- if and (ne .Values.updateStrategy.type "Recreate") (eq .Values.gateway.mode "read-write") -}}
{{- fail "gateway.mode=read-write requires updateStrategy.type=Recreate to avoid overlapping writers during rollouts" -}}
{{- end -}}
{{- if and (eq .Values.gateway.mode "read-write") (gt (int .Values.replicaCount) 1) -}}
{{- fail "gateway.mode=read-write currently supports replicaCount=1; use restore-readonly for scaled restore readers" -}}
{{- end -}}
{{- if not (gt (int64 .Values.hardening.maxPutObjectBytes) 0) -}}
{{- fail "hardening.maxPutObjectBytes must be greater than zero" -}}
{{- end -}}
{{- if not (gt (int64 .Values.hardening.bufferedPutObjectBytes) 0) -}}
{{- fail "hardening.bufferedPutObjectBytes must be greater than zero" -}}
{{- end -}}
{{- if gt (int64 .Values.hardening.bufferedPutObjectBytes) (int64 .Values.hardening.maxPutObjectBytes) -}}
{{- fail "hardening.bufferedPutObjectBytes must be less than or equal to hardening.maxPutObjectBytes" -}}
{{- end -}}
{{- if lt (int64 .Values.hardening.backendMultipartPartBytes) 5242880 -}}
{{- fail "hardening.backendMultipartPartBytes must be at least 5242880 bytes" -}}
{{- end -}}
{{- if not (gt (int64 .Values.hardening.maxInFlightUploadBodyBytes) 0) -}}
{{- fail "hardening.maxInFlightUploadBodyBytes must be greater than zero" -}}
{{- end -}}
{{- if not (gt (int .Values.hardening.maxConcurrentConnections) 0) -}}
{{- fail "hardening.maxConcurrentConnections must be greater than zero" -}}
{{- end -}}
{{- if not (gt (int .Values.hardening.maxConcurrentRequests) 0) -}}
{{- fail "hardening.maxConcurrentRequests must be greater than zero" -}}
{{- end -}}
{{- if not (gt (int .Values.hardening.requestRateLimitPerSecond) 0) -}}
{{- fail "hardening.requestRateLimitPerSecond must be greater than zero" -}}
{{- end -}}
{{- if and .Values.repository.retention.mode (not (gt (int .Values.repository.retention.days) 0)) -}}
{{- fail "repository.retention.days must be greater than zero when repository.retention.mode is set" -}}
{{- end -}}
{{- if and (not .Values.repository.retention.mode) (gt (int .Values.repository.retention.days) 0) -}}
{{- fail "repository.retention.mode is required when repository.retention.days is set" -}}
{{- end -}}
{{- if .Values.admin.enabled -}}
{{- if not (gt (int .Values.admin.port) 0) -}}
{{- fail "admin.port must be greater than zero when admin.enabled=true" -}}
{{- end -}}
{{- if and (not .Values.admin.createToken) (not .Values.admin.existingTokenSecret) -}}
{{- fail "admin.createToken=true or admin.existingTokenSecret is required when admin.enabled=true" -}}
{{- end -}}
{{- if and .Values.admin.createToken (not .Values.admin.bearerToken) -}}
{{- fail "admin.bearerToken is required when admin.createToken=true" -}}
{{- end -}}
{{- end -}}
{{- if and (not .Values.repositoryKeys.create) (not .Values.repositoryKeys.existingSecret) -}}
{{- fail "repositoryKeys.create=true or repositoryKeys.existingSecret is required" -}}
{{- end -}}
{{- if and (not .Values.credentials.create) (not .Values.credentials.existingSecret) -}}
{{- fail "credentials.create=true or credentials.existingSecret is required" -}}
{{- end -}}
{{- if and .Values.credentials.create (not .Values.credentials.accessKeyId) -}}
{{- fail "credentials.accessKeyId is required when credentials.create=true" -}}
{{- end -}}
{{- if and .Values.credentials.create (not .Values.credentials.secretAccessKey) -}}
{{- fail "credentials.secretAccessKey is required when credentials.create=true" -}}
{{- end -}}
{{- if and .Values.repositoryKeys.create (not .Values.repositoryKeys.saltHex) -}}
{{- fail "repositoryKeys.saltHex is required when repositoryKeys.create=true" -}}
{{- end -}}
{{- if and .Values.repositoryKeys.create (not .Values.repositoryKeys.wrappingKeyHex) -}}
{{- fail "repositoryKeys.wrappingKeyHex is required when repositoryKeys.create=true" -}}
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

{{- define "rs3-gateway.anchorNamespace" -}}
{{- default .Release.Namespace .Values.anchor.namespace -}}
{{- end -}}
