# HydraHunter: Evolution-driven Vulnerability Clone Detection via Security-aligned LLM Variants

## Prerequisites

- Neo4j: 4.4.41
- Java (OpenJDK): 11.0.2
- Python: 3.11.11
- phpjoern

## Python Dependencies (pinned)

- langgraph==0.4.3
- py2neo-history==2021.2.3
- tree-sitter==0.21.0
- tree-sitter-php==0.23.11

## Run
1. Generate semantic information for known vulnerabilities with patches:
    python signature_generator.py

2. Generate variants and extract signatures from variants:
    python varint_generator_and_siggene.py

3. Process the target project and extract potential vulnerability semantics and signatures:
    python hydra_main_new.py

4. Build the variant signature library, match signatures, and reduce false positives:
    python vuln_detection.py
