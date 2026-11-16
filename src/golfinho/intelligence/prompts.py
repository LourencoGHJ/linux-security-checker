def generate_investigation_prompt(finding, system_info=None):
    system_info = system_info or {}

    system_name = system_info.get(
        "distribution",
        system_info.get("name", system_info.get("family", "Desconhecido")),
    )

    filename = finding.get("filename") or "Não aplicável"

    return f"""
ATUA COMO: Especialista sénior em Linux, Windows e Cybersecurity.

PROJETO: GOLFINHO Security Investigation Toolkit

SISTEMA ANALISADO:
{system_name}

IDENTIFICADOR:
{finding.get("id", "Desconhecido")}

REGRA:
{finding.get("rule_id", "Não identificada")}

OCORRÊNCIA:
{finding.get("title", "Sem título")}

CATEGORIA:
{finding.get("category", "Não identificada")}

GRAVIDADE:
{finding.get("severity", "UNKNOWN")}

CONFIANÇA DA DETEÇÃO:
{finding.get("confidence", "UNKNOWN")}

FICHEIRO RELACIONADO:
{filename}

DESCRIÇÃO:
{finding.get("description", "Sem descrição")}

EVIDÊNCIA:
{finding.get("evidence", "Sem evidência")}

RECOMENDAÇÃO INICIAL:
{finding.get("recommendation", "Sem recomendação")}

OBJETIVO DA INVESTIGAÇÃO:

1. Explica tecnicamente o que foi detetado.
2. Determina se representa realmente um risco de segurança.
3. Identifica possíveis falsos positivos.
4. Explica como validar a ocorrência no sistema analisado.
5. Apresenta comandos de diagnóstico seguros e não destrutivos.
6. Consulta documentação oficial e referências relevantes.
7. Se existir uma CVE aplicável, apresenta o identificador e a fonte.
8. Propõe uma correção fundamentada, caso seja necessária.
9. Explica os possíveis efeitos secundários da correção.

REGRAS:

- Não inventes vulnerabilidades ou CVE.
- Não assumas que uma configuração é perigosa sem contexto.
- Não executes alterações no sistema.
- Distingue factos, hipóteses e recomendações.
- Utiliza português de Portugal.
- Prioriza fontes oficiais e documentação técnica.
""".strip()
