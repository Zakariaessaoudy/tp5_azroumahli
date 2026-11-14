"""Point d'entrée principal de la plateforme AIOps multi-agents."""

from orchestration.orchestrator import run_orchestration


def main():
    return run_orchestration()


if __name__ == "__main__":
    main()
