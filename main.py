from scanner.modules.a07_brute_force import run_brute_force
from scanner.core.scanner import Scanner


base_url = "http://192.168.100.165"

username = "admin"

passwords = [
    "123456",
    "admin123",
    "qwerty",
    "password"
]


scanner = Scanner()
scanner.register_module(run_brute_force)

findings = scanner.run(
    base_url=base_url,
    username=username,
    passwords=passwords
)

print("\n===== SECURESCAN =====")

for index, finding in enumerate(findings, start=1):

    print(f"\n--- Finding {index} ---")

    print(f"Categoria: {finding.category}")
    print(f"Nome: {finding.name}")
    print(f"Teste: {finding.test}")
    print(f"Status: {finding.status}")
    print(f"Severidade: {finding.severity}")
    print(f"Evidência: {finding.evidence}")
    print(f"Recomendação: {finding.recommendation}")

'''scanner faz toda a parte de execução dos testes, chamando o módulo run_brute_force e passando os parâmetros necessários.'''