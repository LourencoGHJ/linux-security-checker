RULES = {
    "GOL-FW-001": {
        "title": "Verificação do firewall incompleta",
        "category": "FIREWALL",
        "severity": "INFO",
        "description": (
            "Não foi possível consultar todos os detalhes do firewall "
            "com os privilégios atuais."
        ),
        "recommendation": (
            "Executar novamente a auditoria com privilégios administrativos "
            "para obter informação mais completa."
        ),
    },
    "GOL-SVC-001": {
        "title": "Serviços com falhas",
        "category": "SERVICES",
        "severity": "LOW",
        "description": (
            "Foram encontrados serviços systemd em estado de falha. "
            "Este resultado não demonstra, por si só, uma vulnerabilidade."
        ),
        "recommendation": (
            "Identificar os serviços afetados e analisar os respetivos "
            "registos antes de decidir qualquer alteração."
        ),
    },
    "GOL-PERM-001": {
        "title": "Permissões de ficheiros a rever",
        "category": "PERMISSIONS",
        "severity": "MEDIUM",
        "description": (
            "Uma ou mais verificações de permissões identificaram "
            "condições que necessitam de análise."
        ),
        "recommendation": (
            "Verificar o proprietário, grupo e permissões do ficheiro "
            "e comparar com a política de segurança aplicável."
        ),
    },
}


def get_rule(rule_id):
    return RULES.get(rule_id)


def list_rules():
    return [
        {"id": rule_id, **details}
        for rule_id, details in RULES.items()
    ]
