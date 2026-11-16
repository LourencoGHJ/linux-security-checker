from linux_security_checker.checks import check_firewall
from linux_security_checker.users import check_users
from linux_security_checker.services import check_services
from linux_security_checker.permissions import check_permissions


# Terminal colors
RESET = "\033[0m"
BOLD = "\033[1m"
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
GRAY = "\033[90m"


WIDTH = 64


def title(text):
    print(f"\n{CYAN}{BOLD}{'━' * WIDTH}{RESET}")
    print(f"{CYAN}{BOLD}  {text}{RESET}")
    print(f"{CYAN}{BOLD}{'━' * WIDTH}{RESET}")


def subtitle(text):
    print(f"\n{BOLD}{text}{RESET}")
    print(f"{GRAY}{'─' * WIDTH}{RESET}")


def status_text(status):
    translations = {
        "ACTIVE": (GREEN, "ATIVO"),
        "INACTIVE": (YELLOW, "INATIVO"),
        "NOT_INSTALLED": (GRAY, "NÃO INSTALADO"),
        "PERMISSION_DENIED": (YELLOW, "REQUER ADMINISTRADOR"),
        "RULESET_PRESENT": (GREEN, "REGRAS DETETADAS"),
        "RULESET_PRESENT_IPTABLES_NFT": (
            GREEN, "REGRAS DETETADAS (UFW / IPTABLES-NFT)"
        ),
        "EMPTY_RULESET": (RED, "SEM REGRAS DETETADAS"),
        "ERROR": (RED, "ERRO NA VERIFICAÇÃO"),
        "UNKNOWN": (YELLOW, "ESTADO DESCONHECIDO"),
        "SYSTEMD_UNAVAILABLE": (YELLOW, "SYSTEMD INDISPONÍVEL"),
        "PERMISSION_DENIED": (YELLOW, "REQUER ADMINISTRADOR"),
    }

    color, label = translations.get(
        status,
        (YELLOW, status.replace("_", " ")),
    )

    return f"{color}{label}{RESET}"


def print_list(items, empty_message="Nenhum resultado encontrado."):
    if not items:
        print(f"  {GRAY}{empty_message}{RESET}")
        return

    for item in items:
        print(f"  {CYAN}•{RESET} {item}")


def print_summary(firewall, users, services, permissions):
    attention = []

    if any(
        value in {"PERMISSION_DENIED", "ERROR", "UNKNOWN"}
        for value in firewall.values()
    ):
        attention.append(
            "Algumas verificações do firewall exigem atenção ou privilégios de administrador."
        )

    if services["status"] != "OK":
        attention.append("A auditoria dos serviços foi parcialmente concluída.")

    permission_issues = [
        item for item in permissions
        if item["status"] not in {"OK", "NOT_FOUND"}
    ]

    if permission_issues:
        attention.append("Existem permissões de ficheiros que precisam de revisão.")

    title("RESUMO DA AUDITORIA")

    print(f"  Contas com privilégios de root: {len(users['uid_zero_accounts'])}")
    print(
        "  Utilizadores em grupos administrativos: "
        f"{sum(len(m) for m in users['privileged_group_members'].values())}"
    )
    print(f"  Serviços em execução: {len(services['running_services'])}")
    print(f"  Serviços com falhas: {len(services['failed_services'])}")
    print(
        "  Ficheiros críticos analisados: "
        f"{len(permissions)}"
    )

    if attention:
        print(f"\n  {YELLOW}{BOLD}PONTOS A TER EM CONTA{RESET}")
        for item in attention:
            print(f"  {YELLOW}•{RESET} {item}")
    else:
        print(f"\n  {GREEN}Não foram detetados problemas nas verificações realizadas.{RESET}")


def main():
    print(f"\n{CYAN}{BOLD}")
    print("  ╔══════════════════════════════════════════════════════════╗")
    print("  ║                                                          ║")
    print("  ║              LINUX SECURITY CHECKER                      ║")
    print("  ║          Auditoria de segurança do sistema                ║")
    print("  ║                                                          ║")
    print("  ╚══════════════════════════════════════════════════════════╝")
    print(f"{RESET}")

    print(f"  {GRAY}Análise local • Apenas leitura • Sem alterações no sistema{RESET}")

    # Collect audit results
    firewall = check_firewall()
    users = check_users()
    services = check_services()
    permissions = check_permissions()

    # Summary
    print_summary(firewall, users, services, permissions)

    # Firewall
    title("01  |  FIREWALL E PROTEÇÃO DE REDE")

    print("  Verificação dos mecanismos de proteção de ligações de rede.\n")

    firewall_descriptions = {
        "ufw": "UFW — gestão simplificada do firewall",
        "firewalld": "Firewalld — gestão dinâmica do firewall",
        "nftables": "Nftables — regras de filtragem de rede",
        "nftables_service": "Serviço nftables — arranque através do systemd",
    }

    for component, status in firewall.items():
        description = firewall_descriptions.get(component, component)
        print(f"  {description}")
        print(f"    Estado: {status_text(status)}\n")

    # Users
    title("02  |  UTILIZADORES E ACESSOS")

    print("  Verificação de contas e privilégios administrativos.\n")

    print(
        f"  Contas com UID 0: "
        f"{len(users['uid_zero_accounts'])}"
    )
    print_list(users["uid_zero_accounts"])

    print("\n  Grupos com privilégios administrativos:")

    if users["privileged_group_members"]:
        for group, members in users["privileged_group_members"].items():
            print(f"\n  Grupo: {group}")
            print_list(members)
    else:
        print(f"  {GRAY}Nenhum grupo identificado.{RESET}")

    print(
        f"\n  Contas com possibilidade de início de sessão: "
        f"{len(users['interactive_users'])}"
    )
    print_list(users["interactive_users"])

    # Services
    title("03  |  SERVIÇOS DO SISTEMA")

    print("  Análise dos serviços geridos pelo systemd.\n")
    print(f"  Estado da análise: {status_text(services['status'])}")

    print(
        f"\n  Serviços atualmente em execução: "
        f"{len(services['running_services'])}"
    )
    print_list(services["running_services"])

    print(
        f"\n  Serviços configurados para iniciar automaticamente: "
        f"{len(services['enabled_services'])}"
    )
    print_list(services["enabled_services"])

    print(
        f"\n  Serviços com falhas: "
        f"{len(services['failed_services'])}"
    )
    print_list(
        services["failed_services"],
        "Não foram encontradas falhas.",
    )

    # Permissions
    title("04  |  PERMISSÕES DE FICHEIROS")

    print("  Verificação de ficheiros importantes do Linux.\n")

    for result in permissions:
        print(f"  {BOLD}{result['path']}{RESET}")
        print(f"    Estado: {status_text(result['status'])}")

        if "permissions" in result:
            print(f"    Permissões: {result['permissions']}")
            print(f"    Proprietário: UID {result['owner_uid']}")
            print(f"    Grupo: GID {result['group_gid']}")

        for finding in result["findings"]:
            print(f"    {YELLOW}• {finding}{RESET}")

        print()

    # Footer
    print(f"{CYAN}{'━' * WIDTH}{RESET}")
    print(f"{BOLD}  AUDITORIA CONCLUÍDA{RESET}")
    print(f"{GRAY}  Linux Security Checker | Educational Security Tool{RESET}")
    print(f"{GRAY}  Os resultados devem ser interpretados no contexto do sistema.{RESET}")
    print(f"{CYAN}{'━' * WIDTH}{RESET}\n")


if __name__ == "__main__":
    main()
