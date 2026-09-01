import sys
from scanner.ai.interpreter import AIInterpreter
from scanner.core.scanner import Scanner
from scanner.modules.a03_command_injection import run_command_injection
from scanner.modules.a03_sql_injection import run_sql_injection
from scanner.modules.a03_xss import run_xss
from scanner.modules.a07_brute_force import run_brute_force
from scanner.utils.dvwa import create_dvwa_session

# Configuração de codificação UTF-8 para garantir a correta renderização de acentos no terminal Windows
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except AttributeError:
        pass


# Configurações do ambiente de teste (DVWA)
base_url = "http://192.168.100.165"
username = "admin"
password = "password"
security_level = "low"

# Wordlist para testes de força bruta (A07)
passwords = [
    "123456",
    "admin123",
    "qwerty",
    "password"
]

print("=" * 60)
print("                    SECURESCAN INICIADO                     ")
print("=" * 60)

# 1. Autenticação centralizada e gestão de sessão no alvo
try:
    print(f"[*] Conectando e autenticando no DVWA ({base_url})...")
    shared_session = create_dvwa_session(
        base_url=base_url,
        username=username,
        password=password,
        security_level=security_level
    )
    print(f"[+] Sessão iniciada com sucesso. Nível de segurança: {security_level.upper()}\n")
except Exception as e:
    print(f"\n[-] Erro ao conectar com o alvo ({base_url}): {e}")
    print("[-] DICA: Certifique-se de que a VM Ubuntu com o container Docker do DVWA está ligada.")
    print("\n" + "=" * 60)
    print("              SCAN INTERROMPIDO (ALVO INACESSÍVEL)          ")
    print("=" * 60)
    sys.exit(1)

# 2. Inicialização do orquestrador
scanner = Scanner()

# 3. Registro dos módulos de teste (OWASP Top 10)
scanner.register_module(run_brute_force)
scanner.register_module(run_sql_injection)
scanner.register_module(run_xss)
scanner.register_module(run_command_injection)

# 4. Execução dos testes determinísticos
findings = scanner.run(
    base_url=base_url,
    username=username,
    passwords=passwords,
    session=shared_session
)

# 5. Apresentação estruturada dos resultados (Findings)
print("\n" + "=" * 60)
print("                RELATÓRIO DE VULNERABILIDADES               ")
print("=" * 60)

if not findings:
    print("\nNenhum achado gerado durante o scan.")
else:
    for index, finding in enumerate(findings, start=1):
        print(f"\n--- Finding {index} ---")
        print(f"Categoria:    {finding.category}")
        print(f"Nome:         {finding.name}")
        print(f"Teste:        {finding.test}")
        print(f"Status:       {finding.status.upper()}")
        print(f"Severidade:   {finding.severity.upper()}")
        print(f"Evidência:    {finding.evidence}")
        print(f"Recomendação: {finding.recommendation}")

# 6. Camada de Inteligência Artificial: Interpretação e Contextualização
print("\n" + "=" * 60)
print("          INTERPRETAÇÃO E ANÁLISE EXECUTIVA (IA)            ")
print("=" * 60)
print("\n[*] Processando achados através da camada de Inteligência Artificial...\n")

ai_interpreter = AIInterpreter()
ai_report = ai_interpreter.interpret_findings(findings)

print(ai_report)

print("\n" + "=" * 60)
print("                        SCAN CONCLUÍDO                      ")
print("=" * 60)