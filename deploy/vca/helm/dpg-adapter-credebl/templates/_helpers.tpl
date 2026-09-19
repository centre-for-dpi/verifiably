{{/*
SPDX-License-Identifier: Apache-2.0
Shared names of the chart.
*/}}
{{- define "vca.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "vca.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "vca.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "vca.labels" -}}
app.kubernetes.io/name: {{ include "vca.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: vca
{{- end -}}

{{- define "vca.selectorLabels" -}}
app.kubernetes.io/name: {{ include "vca.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
