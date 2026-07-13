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

{{- define "rs3-gateway.validateNetworkPolicyPeers" -}}
{{- $label := .label -}}
{{- range $peer := .peers -}}
{{- $ipBlock := default (dict) (get $peer "ipBlock") -}}
{{- $namespaceSelector := default (dict) (get $peer "namespaceSelector") -}}
{{- $podSelector := default (dict) (get $peer "podSelector") -}}
{{- $ipBlockConfigured := not (empty (get $ipBlock "cidr")) -}}
{{- $namespaceConfigured := or (not (empty (get $namespaceSelector "matchLabels"))) (not (empty (get $namespaceSelector "matchExpressions"))) -}}
{{- $podConfigured := or (not (empty (get $podSelector "matchLabels"))) (not (empty (get $podSelector "matchExpressions"))) -}}
{{- if not (or $ipBlockConfigured (or $namespaceConfigured $podConfigured)) -}}
{{- fail (printf "%s must contain a non-empty ipBlock, namespaceSelector, or podSelector" $label) -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "rs3-gateway.validateValues" -}}
{{- if and (ne .Values.admin.profile "local") (ne .Values.admin.profile "production") -}}
{{- fail "admin.profile must be local or production" -}}
{{- end -}}
{{- if and .Values.image.digest (not (regexMatch "^sha256:[a-f0-9]{64}$" .Values.image.digest)) -}}
{{- fail "image.digest must be an immutable sha256:<64 lowercase hex characters> digest" -}}
{{- end -}}
{{- if and (not .Values.image.digest) (not .Values.image.tag) -}}
{{- fail "image.tag is required when image.digest is empty" -}}
{{- end -}}
{{- if .Values.networkPolicy.enabled -}}
{{- include "rs3-gateway.validateNetworkPolicyPeers" (dict "label" "networkPolicy.egress.backend.to peers" "peers" .Values.networkPolicy.egress.backend.to) -}}
{{- include "rs3-gateway.validateNetworkPolicyPeers" (dict "label" "networkPolicy.egress.kubeApi.to peers" "peers" .Values.networkPolicy.egress.kubeApi.to) -}}
{{- include "rs3-gateway.validateNetworkPolicyPeers" (dict "label" "networkPolicy.egress.dns.to peers" "peers" .Values.networkPolicy.egress.dns.to) -}}
{{- end -}}
{{- if and (ne .Values.image.pullPolicy "Always") (and (ne .Values.image.pullPolicy "IfNotPresent") (ne .Values.image.pullPolicy "Never")) -}}
{{- fail "image.pullPolicy must be Always, IfNotPresent, or Never" -}}
{{- end -}}
{{- if eq .Values.admin.profile "production" -}}
{{- if not .Values.admin.enabled -}}
{{- fail "admin.profile=production requires admin.enabled=true for readiness and path-redacted operator status" -}}
{{- end -}}
{{- if not .Values.image.digest -}}
{{- fail "admin.profile=production requires image.digest; mutable image tags are local-development only" -}}
{{- end -}}
{{- if or .Values.credentials.create (or .Values.admin.createToken (or .Values.backendCredentials.create .Values.repositoryKeys.create)) -}}
{{- fail "admin.profile=production forbids chart-created secret values because Helm stores them in release history; use existing Secret references" -}}
{{- end -}}
{{- if and (ne .Values.backend.endpoint "s3") (not (hasPrefix "https://" .Values.backend.endpoint)) -}}
{{- fail "admin.profile=production requires backend.endpoint=s3 or an https:// endpoint" -}}
{{- end -}}
{{- if and (eq .Values.gateway.mode "read-write") (ne .Values.anchor.mode "kubernetes-lease") -}}
{{- fail "admin.profile=production with gateway.mode=read-write requires anchor.mode=kubernetes-lease" -}}
{{- end -}}
{{- if and (eq .Values.gateway.mode "read-write") (ne .Values.gateway.writerGuard "required") -}}
{{- fail "admin.profile=production with gateway.mode=read-write requires gateway.writerGuard=required" -}}
{{- end -}}
{{- if and (eq .Values.gateway.mode "read-write") (not .Values.repository.retention.mode) -}}
{{- fail "admin.profile=production with gateway.mode=read-write requires repository retention" -}}
{{- end -}}
{{- if and (eq .Values.gateway.mode "read-write") (not .Values.providerConformance.existingConfigMap) -}}
{{- fail "admin.profile=production with gateway.mode=read-write requires providerConformance.existingConfigMap with current retained-provider evidence" -}}
{{- end -}}
{{- if .Values.repository.allowInit -}}
{{- fail "admin.profile=production requires repository.allowInit=false outside deliberate bootstrap" -}}
{{- end -}}
{{- if not (regexMatch "^ed25519:[a-fA-F0-9]{64}$" .Values.recovery.publicKey) -}}
{{- fail "admin.profile=production requires recovery.publicKey as ed25519:<64 hex characters>" -}}
{{- end -}}
{{- if .Values.networkPolicy.enabled -}}
{{- $ingressNamespaceSelector := default (dict) .Values.networkPolicy.ingress.namespaceSelector -}}
{{- $ingressPodSelector := default (dict) .Values.networkPolicy.ingress.podSelector -}}
{{- $ingressNamespaceConfigured := or (not (empty (get $ingressNamespaceSelector "matchLabels"))) (not (empty (get $ingressNamespaceSelector "matchExpressions"))) -}}
{{- $ingressPodConfigured := or (not (empty (get $ingressPodSelector "matchLabels"))) (not (empty (get $ingressPodSelector "matchExpressions"))) -}}
{{- if not (or $ingressNamespaceConfigured $ingressPodConfigured) -}}
{{- fail "admin.profile=production with networkPolicy.enabled=true requires a non-empty S3 ingress namespaceSelector or podSelector" -}}
{{- end -}}
{{- if empty .Values.networkPolicy.egress.backend.to -}}
{{- fail "admin.profile=production with networkPolicy.enabled=true requires networkPolicy.egress.backend.to peers" -}}
{{- end -}}
{{- if empty .Values.networkPolicy.egress.kubeApi.to -}}
{{- fail "admin.profile=production with networkPolicy.enabled=true requires networkPolicy.egress.kubeApi.to peers" -}}
{{- end -}}
{{- if empty .Values.networkPolicy.egress.dns.to -}}
{{- fail "admin.profile=production with networkPolicy.enabled=true requires networkPolicy.egress.dns.to peers" -}}
{{- end -}}
{{- if .Values.metrics.enabled -}}
{{- $metricsNamespaceSelector := default (dict) .Values.networkPolicy.ingress.metrics.namespaceSelector -}}
{{- $metricsPodSelector := default (dict) .Values.networkPolicy.ingress.metrics.podSelector -}}
{{- $metricsNamespaceConfigured := or (not (empty (get $metricsNamespaceSelector "matchLabels"))) (not (empty (get $metricsNamespaceSelector "matchExpressions"))) -}}
{{- $metricsPodConfigured := or (not (empty (get $metricsPodSelector "matchLabels"))) (not (empty (get $metricsPodSelector "matchExpressions"))) -}}
{{- if not (or $metricsNamespaceConfigured $metricsPodConfigured) -}}
{{- fail "admin.profile=production with metrics and NetworkPolicy enabled requires a non-empty metrics ingress namespaceSelector or podSelector" -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if not .Values.repository.id -}}
{{- fail "repository.id is required; use a stable value for keyring envelope binding" -}}
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
{{- if .Values.maintenance.mode -}}
{{- if eq .Values.gateway.mode "restore-readonly" -}}
{{- fail "gateway.mode=restore-readonly forces maintenance off and the server rejects RS3_MAINTENANCE_MODE; leave maintenance.mode empty" -}}
{{- end -}}
{{- if and (ne .Values.maintenance.mode "auto") (and (ne .Values.maintenance.mode "manual") (ne .Values.maintenance.mode "off")) -}}
{{- fail "maintenance.mode must be empty, auto, manual, or off" -}}
{{- end -}}
{{- end -}}
{{- if and .Values.maintenance.minCooldownSeconds .Values.maintenance.maxIntervalSeconds -}}
{{- if gt (int64 .Values.maintenance.minCooldownSeconds) (int64 .Values.maintenance.maxIntervalSeconds) -}}
{{- fail "maintenance.minCooldownSeconds must be less than or equal to maintenance.maxIntervalSeconds" -}}
{{- end -}}
{{- end -}}
{{- if and .Values.providerConformance.existingConfigMap (not .Values.providerConformance.reportKey) -}}
{{- fail "providerConformance.reportKey is required when providerConformance.existingConfigMap is set" -}}
{{- end -}}
{{- if not (gt (int64 .Values.providerConformance.maxAgeSeconds) 0) -}}
{{- fail "providerConformance.maxAgeSeconds must be greater than zero" -}}
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
{{- if lt (int64 .Values.hardening.backendMultipartPartBytes) 5242880 -}}
{{- fail "hardening.backendMultipartPartBytes must be at least 5242880 bytes" -}}
{{- end -}}
{{- if not (gt (int64 .Values.hardening.maxInFlightUploadBodyBytes) 0) -}}
{{- fail "hardening.maxInFlightUploadBodyBytes must be greater than zero" -}}
{{- end -}}
{{- if not (gt (int .Values.hardening.requestRateLimitPerSecond) 0) -}}
{{- fail "hardening.requestRateLimitPerSecond must be greater than zero" -}}
{{- end -}}
{{- if and .Values.repository.retention.mode (not (gt (int .Values.repository.retention.days) 0)) -}}
{{- fail "repository.retention.days must be greater than zero when repository.retention.mode is set" -}}
{{- end -}}
{{- $maintenanceMode := .Values.maintenance.mode | default "auto" -}}
{{- $maintenanceHorizon := int64 (.Values.maintenance.renewalHorizonSeconds | default 604800) -}}
{{- $maintenanceMaxInterval := int64 (.Values.maintenance.maxIntervalSeconds | default 604800) -}}
{{- $retentionSeconds := mul (int64 .Values.repository.retention.days) 86400 -}}
{{- if and .Values.repository.retention.mode (and (eq .Values.gateway.mode "read-write") (eq $maintenanceMode "auto")) -}}
{{- if le $retentionSeconds (add $maintenanceHorizon $maintenanceMaxInterval) -}}
{{- fail "automatic maintenance requires repository.retention.days to exceed maintenance.maxIntervalSeconds plus maintenance.renewalHorizonSeconds; include additional outage and response margin" -}}
{{- end -}}
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
{{- if and .Values.admin.mutationBearerToken (not .Values.admin.createToken) -}}
{{- fail "admin.mutationBearerToken requires admin.createToken=true; otherwise add a mutation-bearer-token key to admin.existingTokenSecret" -}}
{{- end -}}
{{- if and .Values.admin.mutationBearerToken (lt (len .Values.admin.mutationBearerToken) 16) -}}
{{- fail "admin.mutationBearerToken must be at least 16 bytes" -}}
{{- end -}}
{{- if and .Values.admin.mutationBearerToken (eq .Values.admin.mutationBearerToken .Values.admin.bearerToken) -}}
{{- fail "admin.mutationBearerToken must differ from admin.bearerToken" -}}
{{- end -}}
{{- end -}}
{{- if .Values.metrics.enabled -}}
{{- if not (gt (int .Values.metrics.port) 0) -}}
{{- fail "metrics.port must be greater than zero when metrics.enabled=true" -}}
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
