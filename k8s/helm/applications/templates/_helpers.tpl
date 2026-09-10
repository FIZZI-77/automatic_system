{{- define "applications.image" -}}
{{- $root := .root -}}
{{- $name := .name -}}
{{- $application := index $root.Values.applications $name -}}
{{- if $root.Values.globalImage.registry -}}
{{- $tag := default $root.Values.globalImage.tag (index (default dict $root.Values.globalImage.tags) $name) -}}
{{ printf "%s/automatic-system-%s:%s" $root.Values.globalImage.registry $name (required "an application image tag is required when globalImage.registry is set" $tag) }}
{{- else -}}
{{ printf "%s:%s" $application.image.repository $application.image.tag }}
{{- end -}}
{{- end -}}

{{- define "applications.dispatchLabels" -}}
app.kubernetes.io/name: dispatch-service
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: backend
app.kubernetes.io/part-of: automatic-system
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/environment: {{ .Values.environment }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- end -}}

{{- define "applications.dispatchSelectorLabels" -}}
app: dispatch-service
{{- end -}}

{{- define "applications.dispatchConfig" -}}
{{- range $key, $value := .Values.dispatch.config }}
{{ $key }}: {{ $value | quote }}
{{- end }}
{{- end -}}

{{- define "applications.dispatchImage" -}}
{{- if .Values.globalImage.registry -}}
{{- $tag := default .Values.globalImage.tag (index (default dict .Values.globalImage.tags) "dispatch") -}}
{{ printf "%s/automatic-system-dispatch:%s" .Values.globalImage.registry (required "a dispatch image tag is required when globalImage.registry is set" $tag) }}
{{- else -}}
{{ printf "%s:%s" (required "dispatch.image.repository is required" .Values.dispatch.image.repository) (required "dispatch.image.tag is required" .Values.dispatch.image.tag) }}
{{- end -}}
{{- end -}}

{{- define "applications.dispatchMigrationImage" -}}
{{- if .Values.migrations.registry -}}
{{- $tag := default .Values.migrations.tag (index (default dict .Values.migrations.tags) "dispatch") -}}
{{ printf "%s/automatic-system-dispatch-migrator:%s" .Values.migrations.registry (required "a dispatch migration image tag is required" $tag) }}
{{- else -}}
{{ printf "%s:%s" (required "dispatch.migration.image.repository is required" .Values.dispatch.migration.image.repository) (required "dispatch.migration.image.tag is required" .Values.dispatch.migration.image.tag) }}
{{- end -}}
{{- end -}}
