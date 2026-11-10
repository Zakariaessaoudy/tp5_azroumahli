"""Point d'entrée de la plateforme AIOps — étape 1."""

from analysis.data_analysis import run_step1
from analysis.report_generator import generate_step1_report


def main():
    results = run_step1()
    generate_step1_report(results)


if __name__ == "__main__":
    main()
