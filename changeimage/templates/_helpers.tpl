{{/*
Expand the name of the chart.
*/}}
{{- define "changeimage.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "changeimage.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "changeimage.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "changeimage.labels" -}}
helm.sh/chart: {{ include "changeimage.chart" . }}
{{ include "changeimage.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "common.labels" -}}
{{- $labels := dict -}}
{{- $labels = merge $labels (dict "helm.sh/chart" (include "changeimage.chart" .)) -}}
{{- $labels = merge $labels (include "changeimage.selectorLabels" . | fromYaml) -}}
{{- if .Chart.AppVersion }}
{{- $labels = merge $labels (dict "app.kubernetes.io/version" .Chart.AppVersion) -}}
{{- end }}
{{- $labels = merge $labels (dict "app.kubernetes.io/managed-by" .Release.Service) -}}
{{- toJson $labels | trimAll "\n" }} 
{{- end }}

{{/*
Selector labels
*/}}
{{- define "changeimage.selectorLabels" -}}
app.kubernetes.io/name: {{ include "changeimage.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "changeimage.affinityDesc" -}}
- key: app.kubernetes.io/name
  operator: In
  values:
    - {{ include "changeimage.name" . }}
- key: app.kubernetes.io/instance
  operator: In
  values:
    - {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "changeimage.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "changeimage.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}
