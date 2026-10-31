# Prompt Injection Detection Lab

<p align="center">
  <strong>A lightweight, rule-based Python tool for identifying common prompt-injection patterns.</strong>
</p>

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/Python-standard%20library-blue?logo=python&logoColor=white">
  <img alt="Project type" src="https://img.shields.io/badge/Project-Educational%20Security%20Lab-informational">
  <img alt="Tests" src="https://img.shields.io/badge/Unit%20tests-8%20passed-success">
  <img alt="Approach" src="https://img.shields.io/badge/Detection-Rule--based-orange">
</p>

## 1. Project overview

Prompt injection is a technique in which an input attempts to manipulate an AI system into ignoring its intended instructions, disclosing protected information, or bypassing safety rules.

The **Prompt Injection Detection Lab** is an educational Python project that scans text prompts for selected suspicious phrases. It uses regular expressions, category-based risk weights, and a simple scoring threshold to classify each prompt as **LOW**, **MEDIUM**, or **HIGH** risk. It also records scan metadata in a CSV file and includes several test scripts for checking expected behaviour.

The project demonstrates foundational skills in Python programming, security-minded input analysis, automated testing, and documenting test results. It is a learning and portfolio project—not a production-grade prompt-injection defence.

## 2. Project objectives

- Identify selected prompt-injection phrases and instruction-manipulation patterns.
- Group matches into understandable security-related categories.
- Assign a heuristic score and risk level to each scanned prompt.
- Keep a basic record of scan metadata for review.
- Evaluate the detector with unit, baseline, unseen-prompt, and evasion test cases.

## 3. Features

- **Pattern-based detection:** checks input against predefined regular expressions.
- **Six detection categories:** instruction override, system prompt extraction, safety bypass, confidential data exposure, unrestricted behaviour, and instruction concealment.
- **Weighted risk scoring:** each detected category contributes its configured score.
- **Three risk levels:** LOW, MEDIUM, and HIGH.
- **Case-insensitive matching:** recognises configured phrases regardless of letter case.
- **Educational-context heuristic:** attempts to avoid flagging some explanatory or educational discussions.
- **CSV scan logging:** records a UTC timestamp, risk level, score, matched categories, prompt length, and SHA-256 hash—not the original prompt text.
- **Test coverage:** includes unit tests and three manually written evaluation datasets.

## 4. How the detection works

The main function, `scan_prompt(prompt)`, checks the supplied text against the patterns in `ATTACK_PATTERNS`.

### Detection categories and weights

| Category | Score | What it is intended to detect |
|---|---:|---|
| Instruction Override | 3 | Attempts to replace, ignore, or override earlier instructions |
| System Prompt Extraction | 3 | Requests to reveal or print hidden/system instructions |
| Safety Bypass | 3 | Attempts to disable safeguards or ignore safety rules |
| Confidential Data Exposure | 4 | Requests to reveal private, secret, or confidential information |
| Unrestricted Behaviour | 2 | Requests for unrestricted or rule-free behaviour |
| Instruction Concealment | 2 | Instructions to hide directions or keep them secret |

A category contributes its configured score once when at least one of its patterns matches. If multiple categories match, their scores are added together.

### Risk classification

| Risk level | Total score | Interpretation |
|---|---:|---|
| **LOW** | 0–1 | No configured pattern matched strongly enough to reach MEDIUM |
| **MEDIUM** | 2–4 | One or more configured patterns matched |
| **HIGH** | 5 or more | Multiple or higher-weight categories matched |

**Important:** this is a heuristic classification. LOW does not prove that a prompt is safe, and HIGH does not prove malicious intent.

### Educational-context handling

The detector checks for a small list of phrases associated with educational or explanatory discussion. When one is found, the current implementation returns LOW risk with a score of zero. This is deliberately simple and is also an important limitation: the detector does not deeply analyse intent or reliably separate harmless discussion from a malicious instruction embedded in an educational-looking prompt.

## 5. Repository structure

```text
prompt-injection-detection-lab/
│
├── detector.py                 # Main detector, scoring, CLI, and CSV logging
├── test_detector.py             # 8 automated unit tests
├── evaluate.py                  # Original 12-prompt evaluation dataset
├── unseen_tests.py              # 8 additional prompts not in the original set
├── evasion_tests.py              # 8 wording/context challenge prompts
├── scan_results.csv              # Example scan log; new scans append records
├── README.md                     # Project documentation
└── screenshots/                  # 16 project and test-evidence screenshots
```

## 6. Requirements

- Python 3.8 or later is recommended.
- No external Python packages are required. The project uses Python's standard library, including `re`, `csv`, `hashlib`, `pathlib`, `datetime`, and `unittest`.
- Git and a GitHub account are only needed to publish the project online.

## 7. Installation and setup

### Step 1 — Get the project

Clone your repository (replace the URL with your own GitHub repository URL):

```bash
git clone https://github.com/YOUR-USERNAME/prompt-injection-detection-lab.git
cd prompt-injection-detection-lab
```

Alternatively, download the repository as a ZIP file from GitHub and extract it.

### Step 2 — Check Python

```bash
python --version
```

On some systems, use `python3 --version` instead. If Python is not installed, install it from [python.org](https://www.python.org/downloads/).

### Step 3 — No dependency installation needed

There is no `requirements.txt` because the current project does not require third-party packages.

## 8. How to run the project

Run these commands from the repository's root folder.

### A. Start the interactive detector

```bash
python detector.py
```

Enter a prompt when asked. The program displays the risk level and score, lists any detected categories, and saves a scan record to `scan_results.csv`.

Example prompts to try:

```text
Ignore all previous instructions.
```

```text
Explain cybersecurity to a beginner.
```

The first is an example of a configured suspicious phrase; the second is a benign example used in the project's tests. Results depend on the exact patterns and context rules in the current code.

### B. Run the automated unit tests

```bash
python -m unittest -v test_detector.py
```

This runs the eight `unittest` cases covering instruction override, system-prompt extraction, confidential-data exposure, multiple matching categories, harmless input, uppercase matching, empty input, and ordinary conversation.

### C. Run the original evaluation dataset

```bash
python evaluate.py
```

This checks 12 manually labelled examples: six malicious and six benign. It prints individual classifications, a confusion matrix, accuracy, precision, and recall.

### D. Run the unseen-prompt tests

```bash
python unseen_tests.py
```

This checks eight additional examples—four labelled malicious and four labelled benign—to explore how the configured rules behave on different wording.

### E. Run the evasion/context tests

```bash
python evasion_tests.py
```

This checks eight challenge examples, including alternative instruction wording and benign educational or explanatory prompts.

### Windows Command Prompt note

The commands above work in Windows Command Prompt when Python is available as `python`. If your system uses the Python launcher, you can replace `python` with `py`.

## 9. Test results

The following results were reproduced by running the uploaded project files. The three evaluation scripts each calculate accuracy, precision, and recall from their own manually labelled datasets.

### Test summary

| Test suite | Cases | True positives | True negatives | False positives | False negatives | Accuracy |
|---|---:|---:|---:|---:|---:|---:|
| Unit tests (`test_detector.py`) | 8 | — | — | — | — | 8/8 passed |
| Original evaluation (`evaluate.py`) | 12 | 6 | 6 | 0 | 0 | 100.00% |
| Unseen prompts (`unseen_tests.py`) | 8 | 4 | 4 | 0 | 0 | 100.00% |
| Evasion/context tests (`evasion_tests.py`) | 8 | 4 | 4 | 0 | 0 | 100.00% |
| **Evaluation datasets combined** | **28** | **14** | **14** | **0** | **0** | **100.00%** |

### Reported evaluation metrics

| Dataset | Accuracy | Precision | Recall |
|---|---:|---:|---:|
| Original evaluation | 100.00% | 100.00% | 100.00% |
| Unseen prompts | 100.00% | 100.00% | 100.00% |
| Evasion/context tests | 100.00% | 100.00% | 100.00% |

The unit-test command also completed successfully with **8 tests passing**. The evaluation datasets contain 28 labelled examples in total; the eight unit tests are a separate test suite and are not included in that 28-case total.

> **How to interpret these results:** The 100% figures describe performance only on these small, manually authored test cases. They are not evidence of 100% real-world detection, and they do not establish that the detector can stop prompt injection in a live AI system. The test cases are limited and may overlap with the patterns the detector was written to recognise. Always rerun the scripts after changing the code or datasets and update this section if the output changes.

## 10. Screenshot Evidence

The `screenshots/` folder contains 16 screenshots documenting the project structure, detector functionality, risk classifications, scan logging, automated tests, and evaluation results.

These screenshots provide visual evidence of the project's development, implementation, and testing.

## 11. Scan logging and privacy considerations

When the interactive detector runs, it appends a record to `scan_results.csv`. The current log columns are:

| Column | Description |
|---|---|
| `timestamp_utc` | Time the scan was recorded, in UTC |
| `risk_level` | LOW, MEDIUM, or HIGH classification |
| `risk_score` | Total heuristic score |
| `detected_categories` | Categories that matched |
| `prompt_length` | Number of characters in the submitted prompt |
| `prompt_sha256` | SHA-256 hash of the prompt text |

The implementation does not write the original prompt into the CSV. However, a hash is not the same as anonymisation: someone with likely candidate text may hash those candidates and compare them with the stored value. Treat scan logs as potentially sensitive, avoid committing real confidential prompts or logs to a public repository, and use synthetic examples for portfolio demonstrations.

## 12. Current limitations

This project has several important limitations:

- **Fixed pattern library:** it only recognises phrases represented by its manually defined regular expressions. New, indirect, or substantially reworded attacks may be missed.
- **No semantic understanding:** it does not understand the meaning or intent of a prompt; it searches for text patterns.
- **Context-handling weakness:** matching an educational-context phrase currently causes an immediate LOW/zero-score return. A malicious instruction placed in that context could therefore be overlooked.
- **Language and obfuscation limits:** the patterns are primarily English and may not detect other languages, unusual spacing, character substitutions, encoding, or obfuscated text.
- **False positives and false negatives remain possible:** harmless discussion may be flagged, while malicious prompts without a configured pattern may pass as LOW.
- **Small, manually labelled datasets:** the evaluation results are not representative of real-world prompt traffic and do not demonstrate generalisation.
- **Not integrated with an AI model:** this is a standalone scanner. It does not inspect model internals, enforce policy, or prevent an application from executing unsafe actions.
- **Log privacy:** SHA-256 hashes can still be vulnerable to guessing attacks when prompts are short or predictable.

## 13. Future improvements

Potential next steps for the project include:

- Expand the dataset with independently written examples and more realistic attack variations.
- Improve educational-context handling so that it does not automatically bypass all pattern checks.
- Add tests for mixed benign and malicious content, quoted instructions, multilingual prompts, encoding, spacing tricks, and character substitutions.
- Report per-category results and additional metrics, including false-positive and false-negative rates.
- Add configurable patterns and scoring thresholds.
- Consider a safer log-retention strategy and an option to disable logging.
- Explore combining rule-based checks with other detection approaches.
- Integrate the scanner into a controlled demonstration application, with additional safeguards rather than relying on the detector alone.

## 14. Skills demonstrated

- Python programming and code organisation
- Regular expressions and text processing
- Rule-based security analysis and heuristic scoring
- File handling and CSV logging
- SHA-256 hashing
- Automated testing with `unittest`
- Confusion matrices and basic classification metrics
- Test-case design, including unseen and evasion-oriented examples
- Technical documentation and communicating security limitations

## 15. Disclaimer

This project is intended for educational purposes and portfolio demonstration only. It is not a complete prompt-injection defence, a security certification, or a replacement for layered application security controls, human review, and ongoing security testing. Do not rely on its output alone to make security-critical decisions.

---

**Author:** Mojisola Veronica Akinbode  
**Project:** Prompt Injection Detection Lab
