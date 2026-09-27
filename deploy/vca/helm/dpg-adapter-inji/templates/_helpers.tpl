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

{{/*
The chart of a service of several roles renders only when the umbrella
chart turns one of its roles on under global.roles (ADR-074). A chart
installed alone, with no global.roles, renders as before.
*/}}
{{- define "vca.enabled" -}}
{{- $global := .Values.global -}}
{{- if not $global -}}
true
{{- else if not $global.roles -}}
true
{{- else -}}
{{- range .Values.roles -}}
{{- $role := index $global.roles . -}}
{{- if $role -}}{{- if $role.enabled -}}true{{- end -}}{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
