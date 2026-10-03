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

{{- /*
The checksum of the peer Secrets of the service (ADR-075). "vca peer
secrets" writes them outside the chart, so the chart reads them from
the cluster. A rotation changes the checksum at the next upgrade, and
the pods roll. Without a cluster, as in "helm template", the checksum
covers no data.
*/ -}}
{{- define "vca.peerChecksum" -}}
{{- $env := .Values.peer.secret | default (printf "%s-%s-peer" .Release.Name .Chart.Name) -}}
{{- $key := .Values.peer.keySecret | default (printf "%s-%s-peer-key" .Release.Name .Chart.Name) -}}
{{- $a := lookup "v1" "Secret" .Release.Namespace $env | default dict -}}
{{- $b := lookup "v1" "Secret" .Release.Namespace $key | default dict -}}
{{- printf "%s|%s" (toJson (get $a "data")) (toJson (get $b "data")) | sha256sum -}}
{{- end -}}
