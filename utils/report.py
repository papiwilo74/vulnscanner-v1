from colorama import Fore, Style, init
init(autoreset=True)

COLORS = {
    "Alto":  Fore.RED,
    "Medio": Fore.YELLOW,
    "Bajo":  Fore.CYAN,
}

def print_report(url, all_results):
    print(f"\n{'='*60}")
    print(f"  VulnScanner — Reporte para: {url}")
    print(f"{'='*60}")

    if not all_results:
        print(Fore.GREEN + "\n No se detectaron vulnerabilidades obvias.\n")
        return

    counts = {"Alto": 0, "Medio": 0, "Bajo": 0}

    for r in all_results:
        risk = r["risk"]
        color = COLORS.get(risk, "")
        counts[risk] += 1
        print(f"\n{color}[{risk}] {r['vuln']}")
        print(f"       → {r['detail']}")

    print(f"\n{'─'*60}")
    print(f"  Resumen: "
          f"{Fore.RED}{counts['Alto']} Alto  "
          f"{Fore.YELLOW}{counts['Medio']} Medio  "
          f"{Fore.CYAN}{counts['Bajo']} Bajo")
    print(f"{'='*60}\n")