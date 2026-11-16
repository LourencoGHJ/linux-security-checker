import json
from datetime import datetime, timezone
from html import escape
from pathlib import Path


def _severity_counts(findings):
    levels = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]
    return {
        level: sum(1 for item in findings if item.get("severity") == level)
        for level in levels
    }


def _safe_filename(value):
    return "".join(
        character if character.isalnum() or character in "-_" else "_"
        for character in str(value)
    )


def _format_value(value):
    if isinstance(value, dict):
        return "; ".join(
            f"{key}: {_format_value(item)}"
            for key, item in value.items()
        )
    if isinstance(value, (list, tuple)):
        return ", ".join(_format_value(item) for item in value) or "—"
    if value is None:
        return "—"
    if isinstance(value, bool):
        return "Sim" if value else "Não"
    return str(value)


def _evidence_table(evidence):
    if not isinstance(evidence, dict):
        evidence = {"Evidência": evidence}

    rows = []
    for key, value in evidence.items():
        rows.append(
            "<tr>"
            f"<th>{escape(str(key).replace('_', ' ').capitalize())}</th>"
            f"<td>{escape(_format_value(value))}</td>"
            "</tr>"
        )

    return (
        '<table class="data-table">'
        "<tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )


def _reference_list(references):
    if not references:
        return '<span class="muted">Sem referências disponíveis.</span>'

    items = []
    for reference in references:
        name = escape(str(reference.get("name", "Referência")))
        url = str(reference.get("url", ""))

        if url.startswith(("https://", "http://")):
            items.append(
                f'<a href="{escape(url, quote=True)}" '
                f'target="_blank" rel="noopener noreferrer">{name}</a>'
            )
        else:
            items.append(name)

    return " <span class='separator'>·</span> ".join(items)


def generate_json_report(results, output_dir="reports"):
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    report = {
        "tool": "GOLFINHO",
        "report_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "platform": results.get("platform"),
        "summary": {
            "total_findings": len(results.get("findings", [])),
            "severity_counts": _severity_counts(
                results.get("findings", [])
            ),
            "total_errors": len(results.get("errors", [])),
        },
        "findings": results.get("findings", []),
        "errors": results.get("errors", []),
    }

    destination = output_path / f"golfinho_report_{timestamp}.json"
    destination.write_text(
        json.dumps(report, indent=4, ensure_ascii=False, default=str),
        encoding="utf-8",
    )

    return destination


def generate_html_report(results, output_dir="reports"):
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    generated_at = datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M UTC")

    platform_info = results.get("platform") or {}
    findings = results.get("findings", [])
    errors = results.get("errors", [])
    counts = _severity_counts(findings)

    system_name = (
        platform_info.get("distribution")
        or platform_info.get("name")
        or platform_info.get("family")
        or "Desconhecido"
    )

    system_fields = [
        ("Sistema operativo", system_name),
        ("Versão", platform_info.get("version", "—")),
        ("Kernel", platform_info.get("kernel", "—")),
        ("Arquitetura", platform_info.get("architecture", "—")),
        ("Nome da máquina", platform_info.get("hostname", "—")),
        ("Privilégios administrativos", (
            "Sim" if platform_info.get("is_admin") else "Não"
        )),
    ]

    system_rows = "".join(
        f"<tr><th>{escape(str(label))}</th>"
        f"<td>{escape(str(value))}</td></tr>"
        for label, value in system_fields
    )

    severity_labels = {
        "CRITICAL": "Crítica",
        "HIGH": "Alta",
        "MEDIUM": "Média",
        "LOW": "Baixa",
        "INFO": "Informativa",
        "UNKNOWN": "Desconhecida",
    }

    severity_classes = {
        "CRITICAL": "critical",
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
        "INFO": "info",
        "UNKNOWN": "unknown",
    }

    severity_summary = "".join(
        f'<div class="severity-count">'
        f'<span class="severity-dot {severity_classes[level]}"></span>'
        f'<span>{severity_labels[level]}</span>'
        f'<strong>{counts[level]}</strong>'
        f'</div>'
        for level in severity_labels
    )

    finding_rows = []
    finding_details = []

    for index, finding in enumerate(findings, start=1):
        severity = finding.get("severity", "UNKNOWN")
        label = severity_labels.get(severity, "Desconhecida")
        css_class = severity_classes.get(severity, "unknown")
        finding_id = escape(str(finding.get("id", "—")))
        anchor = f"finding-{index}"

        finding_rows.append(
            f'<tr>'
            f'<td><a href="#{anchor}">{finding_id}</a></td>'
            f'<td>{escape(str(finding.get("rule_id") or "—"))}</td>'
            f'<td>{escape(str(finding.get("title") or "—"))}</td>'
            f'<td>{escape(str(finding.get("category") or "—"))}</td>'
            f'<td><span class="severity-tag {css_class}">{label}</span></td>'
            f'<td>{escape(str(finding.get("confidence") or "—"))}</td>'
            f'</tr>'
        )

        finding_details.append(f"""
        <article class="finding" id="{anchor}">
            <div class="finding-top">
                <div>
                    <span class="finding-id">{finding_id}</span>
                    <h3>{escape(str(finding.get("title") or "Sem título"))}</h3>
                </div>
                <span class="severity-tag {css_class}">{label}</span>
            </div>

            <div class="metadata">
                <span>Regra: <strong>{escape(str(finding.get("rule_id") or "—"))}</strong></span>
                <span>Categoria: <strong>{escape(str(finding.get("category") or "—"))}</strong></span>
                <span>Confiança: <strong>{escape(str(finding.get("confidence") or "—"))}</strong></span>
            </div>

            <h4>Descrição</h4>
            <p>{escape(str(finding.get("description") or "—"))}</p>

            <h4>Evidência recolhida</h4>
            {_evidence_table(finding.get("evidence", {}))}

            <h4>Recomendação</h4>
            <p>{escape(str(finding.get("recommendation") or "—"))}</p>

            <h4>Referências técnicas</h4>
            <p class="references">{_reference_list(finding.get("references", []))}</p>
        </article>
        """)

    errors_section = ""
    if errors:
        error_rows = "".join(
            "<tr>"
            f"<td>{escape(str(error.get('check', '—')))}</td>"
            f"<td>{escape(str(error.get('error', '—')))}</td>"
            "</tr>"
            for error in errors
        )
        errors_section = f"""
        <section class="panel" id="errors">
            <h2>Erros de execução</h2>
            <table class="data-table">
                <thead><tr><th>Verificação</th><th>Erro</th></tr></thead>
                <tbody>{error_rows}</tbody>
            </table>
        </section>
        """

    findings_content = (
        "".join(finding_details)
        if finding_details
        else '<p class="empty">Não foram identificadas ocorrências pelas regras disponíveis.</p>'
    )

    findings_table = ""
    if findings:
        findings_table = f"""
        <section class="panel" id="findings">
            <h2>Ocorrências identificadas</h2>
            <input id="findingSearch" class="search-box"
                type="search" placeholder="Pesquisar ocorrências...">
            <div class="table-wrap">
                <table class="data-table findings-table">
                    <thead>
                        <tr>
                            <th>Identificador</th>
                            <th>Regra</th>
                            <th>Descrição</th>
                            <th>Categoria</th>
                            <th>Gravidade</th>
                            <th>Confiança</th>
                        </tr>
                    </thead>
                    <tbody>{''.join(finding_rows)}</tbody>
                </table>
            </div>
        </section>
        """

    html = f"""<!DOCTYPE html>
<html lang="pt-PT">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>GOLFINHO | Relatório de auditoria</title>
<style>
:root {{
    color-scheme: light;
    --background: #f4f6f9;
    --surface: #ffffff;
    --text: #202b3c;
    --muted: #687589;
    --border: #e2e7ee;
    --navy: #152b45;
    --link: #245c91;
}}
* {{ box-sizing: border-box; }}
html {{ scroll-behavior: smooth; }}
body {{
    margin: 0;
    background: var(--background);
    color: var(--text);
    font-family: Inter, "Segoe UI", Arial, sans-serif;
    font-size: 14px;
    line-height: 1.6;
}}
header {{
    background: var(--navy);
    color: white;
    padding: 24px max(24px, calc((100% - 1120px) / 2));
}}
.header-content {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 20px;
}}
.brand {{
    font-size: 22px;
    font-weight: 750;
    letter-spacing: 1.5px;
}}
.header-meta {{
    color: #cbd5e1;
    text-align: right;
    font-size: 12px;
}}
nav {{
    background: white;
    border-bottom: 1px solid var(--border);
    padding: 0 max(24px, calc((100% - 1120px) / 2));
    display: flex;
    gap: 24px;
    overflow-x: auto;
}}
nav a {{
    color: var(--muted);
    text-decoration: none;
    padding: 13px 0;
    white-space: nowrap;
    font-weight: 600;
}}
nav a:hover {{ color: var(--link); }}
main {{
    max-width: 1120px;
    margin: 28px auto;
    padding: 0 22px;
}}
.panel {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 9px;
    padding: 23px;
    margin-bottom: 20px;
}}

.mascot {{
    width: 58px;
    height: 58px;
    object-fit: contain;
    vertical-align: middle;
    margin-right: 10px;
    filter: drop-shadow(0 0 12px #22d3ee);
}}
:root {{
    --ocean: #eaf7fc;
}}
body {{
    transition: background .25s, color .25s;
}}
body.dark {{
    --background: #071827;
    --surface: #102b40;
    --text: #e6f6ff;
    --muted: #a4bdce;
    --border: #24465e;
    --navy: #03101e;
    --link: #54d9ff;
}}
body.dark .severity-count,
body.dark .finding .data-table {{
    background: #0b2235;
}}
.search-box {{
    width: 100%;
    max-width: 380px;
    padding: 11px 14px;
    border: 1px solid var(--border);
    border-radius: 7px;
    background: var(--surface);
    color: var(--text);
    margin-bottom: 16px;
}}
.action-button {{
    border: 1px solid #38bdf8;
    border-radius: 7px;
    padding: 9px 14px;
    background: transparent;
    color: inherit;
    cursor: pointer;
    font-weight: 600;
}}
.action-button:hover {{
    background: #0ea5e9;
    color: white;
}}
body.dark .panel,
body.dark .finding {{
    box-shadow: 0 8px 30px #0005;
}}
h2 {{
    margin: 0 0 18px;
    font-size: 17px;
    font-weight: 700;
}}
h3 {{ font-size: 16px; margin: 5px 0 0; }}
h4 {{
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: .5px;
    color: var(--muted);
    margin: 22px 0 7px;
}}
p {{ margin: 5px 0; }}
.system-grid {{
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 0 24px;
}}
.data-table {{
    width: 100%;
    border-collapse: collapse;
    text-align: left;
}}
.data-table th,
.data-table td {{
    border-bottom: 1px solid var(--border);
    padding: 11px 12px;
    vertical-align: top;
}}
.data-table th {{
    width: 210px;
    color: var(--muted);
    font-weight: 600;
}}
.data-table tr:last-child th,
.data-table tr:last-child td {{ border-bottom: 0; }}
.findings-table th {{ width: auto; }}
.findings-table th,
.findings-table td {{ white-space: nowrap; }}
.findings-table td:nth-child(3) {{ white-space: normal; }}
.table-wrap {{ overflow-x: auto; }}
.summary-grid {{
    display: grid;
    grid-template-columns: repeat(6, minmax(0, 1fr));
    gap: 10px;
}}
.severity-count {{
    display: flex;
    align-items: center;
    gap: 8px;
    background: #f8fafc;
    border: 1px solid var(--border);
    border-radius: 7px;
    padding: 12px;
}}
.severity-count strong {{
    margin-left: auto;
    font-size: 18px;
}}
.severity-dot {{
    width: 9px;
    height: 9px;
    border-radius: 50%;
    flex: 0 0 auto;
}}
.critical {{ background: #991b1b; }}
.high {{ background: #dc4444; }}
.medium {{ background: #d18b27; }}
.low {{ background: #3975ae; }}
.info {{ background: #64748b; }}
.unknown {{ background: #94a3b8; }}
.severity-tag {{
    display: inline-block;
    padding: 3px 9px;
    border-radius: 4px;
    color: white;
    font-size: 11px;
    font-weight: 700;
    white-space: nowrap;
}}
.finding {{
    background: white;
    border: 1px solid var(--border);
    border-radius: 9px;
    padding: 22px 24px;
    margin-bottom: 15px;
    scroll-margin-top: 20px;
}}
.finding-top {{
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 16px;
}}
.finding-id {{
    color: var(--muted);
    font-size: 12px;
    font-weight: 650;
}}
.metadata {{
    display: flex;
    flex-wrap: wrap;
    gap: 10px 22px;
    margin-top: 14px;
    padding: 10px 0;
    border-top: 1px solid var(--border);
    border-bottom: 1px solid var(--border);
    color: var(--muted);
    font-size: 12px;
}}
.metadata strong {{ color: var(--text); }}
.finding .data-table {{
    background: #f8fafc;
    border: 1px solid var(--border);
    border-radius: 6px;
}}
.finding .data-table th {{ width: 190px; }}
.references a {{
    color: var(--link);
    text-decoration: none;
}}
.references a:hover {{ text-decoration: underline; }}
.separator {{ color: #a0aaba; padding: 0 5px; }}
.empty, .muted {{ color: var(--muted); }}
footer {{
    max-width: 1120px;
    margin: 0 auto;
    padding: 10px 22px 28px;
    color: var(--muted);
    font-size: 12px;
}}
@media (max-width: 760px) {{
    .header-content {{ align-items: flex-start; flex-direction: column; }}
    .header-meta {{ text-align: left; }}
    .system-grid {{ grid-template-columns: 1fr; }}
    .summary-grid {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
    .panel {{ padding: 16px; }}
    .finding {{ padding: 17px; }}
}}
@media print {{
    body {{ background: white; }}
    nav {{ display: none; }}
    main {{ margin: 10px auto; }}
    .panel, .finding {{ break-inside: avoid; }}
    a {{ color: inherit; }}
}}
</style>
</head>
<body>
<header>
    <div class="header-content">
        <div>
            <div class="brand"><img class="mascot" src="../assets/golfinho-mascot.png" alt="Mascote GOLFINHO"> GOLFINHO</div>
            <div>Relatório de auditoria de segurança</div>
        </div>
        <div class="header-meta">
            <div>Security Investigation Toolkit</div>
            <div>Gerado em {generated_at}</div>
        </div>
    </div>
</header>

<nav>
    <a href="#summary">Resumo</a>
    <a href="#system">Sistema</a>
    <a href="#findings">Ocorrências</a>
    <a href="#details">Detalhes</a>
    { '<a href="#errors">Erros</a>' if errors else '' }
<button class="action-button" onclick="toggleTheme()" type="button">
        Alternar tema
    </button>
</nav>

<main>
    <section class="panel" id="summary">
        <h2>Resumo da auditoria</h2>
        <div class="summary-grid">
            {severity_summary}
        </div>
        <p style="margin-top:16px;color:#687589">
            Total de ocorrências: <strong>{len(findings)}</strong>
            &nbsp; | &nbsp;
            Erros de execução: <strong>{len(errors)}</strong>
        </p>
    </section>

    <section class="panel" id="system">
        <h2>Informação do sistema</h2>
        <table class="data-table">
            <tbody>{system_rows}</tbody>
        </table>
    </section>

    {findings_table}

    <section id="details">
        <h2>Detalhe das ocorrências</h2>
        {findings_content}
    </section>

    {errors_section}
</main>

<footer>
    GOLFINHO Security Investigation Toolkit · Relatório {timestamp}
</footer>

<script>
function toggleTheme() {{
    document.body.classList.toggle("dark");
    localStorage.setItem(
        "golfinho-theme",
        document.body.classList.contains("dark") ? "dark" : "light"
    );
}}

if (localStorage.getItem("golfinho-theme") === "dark") {{
    document.body.classList.add("dark");
}}

const search = document.getElementById("findingSearch");

if (search) {{
    search.addEventListener("input", function () {{
        const query = this.value.toLowerCase();

        document.querySelectorAll(".finding").forEach(function (item) {{
            item.style.display = item.innerText.toLowerCase().includes(query)
                ? ""
                : "none";
        }});
    }});
}}
</script>
</body>
</html>
"""

    destination = output_path / f"golfinho_report_{timestamp}.html"
    destination.write_text(html, encoding="utf-8")

    return destination
