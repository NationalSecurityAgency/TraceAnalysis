# Database Schema Description

[![Tables of each collection in the database with links between then according to the following schema description.](schema.png)](schema.png)

## Nodes

{% for node in nodes %}
### <u>`{{node.name}}`</u>

**Description:** {{node.description}}

**Edges:**

{% for edge in edges %}{% if edge.source == node.name or edge.dest == node.name %}
* [**{{edge.name}}**](#{{edge.name}}): [{{edge.source}}](#{{edge.source}}) &#8594; [{{edge.dest}}](#{{edge.dest}}): {{edge.description}}
{% endif %}{% endfor %}

**Attributes:**

| Name | Type | Description | References |
| ---- | ---- | ----------- | ---------- |
{% for attr in node.attributes %}| {{attr.name}} | {{attr.type}} | {{attr.description}} | {% for join in attr.joins %} {{join.table}}.{{join.field}} {% endfor %} |
{% endfor %}
---
{% endfor %}

{% for edge in edges %}
### <u>`{{edge.name}}`</u>

[`{{edge.source}}`](#{{edge.source}}) &#8594; [`{{edge.dest}}`](#{{edge.dest}})

**Description:** {{edge.description}}

**Attributes:**

| Name | Type | Description | References |
| ---- | ---- | ----------- | ---------- |
{% for attr in edge.attributes %}| {{attr.name}} | {{attr.type}} | {{attr.description}} | {% for join in attr.joins %} {{join.table}}.{{join.field}} {% endfor %} |
{% endfor %}
---
{% endfor %}
