# 🔐 Password Strength Checker

A lightweight **command-line password strength checker** written in Python. It evaluates passwords against common security criteria and provides clear, actionable recommendations to improve password hygiene.

This project is intentionally **simple, ethical, and defensive**, making it ideal for a GitHub security portfolio and beginner-friendly cybersecurity demonstrations.

---

## 🎯 Project Objective

Weak passwords are one of the most common causes of account compromise. The goal of this project is to demonstrate:

* How password strength can be evaluated programmatically
* Common patterns attackers exploit in weak passwords
* How users can be guided toward stronger password choices

This tool **does not crack, store, or transmit passwords**. It only performs local analysis.

---

## ⚙️ How It Works

The tool analyzes a password using multiple factors:

1. **Length check** – Longer passwords score higher
2. **Character diversity** – Checks for:

   * Lowercase letters
   * Uppercase letters
   * Digits
   * Special characters
3. **Common password detection** – Flags widely used weak passwords
4. **Pattern analysis** – Detects:

   * Repeated characters (e.g., `aaaa`)
   * Sequential patterns (e.g., `abcd`, `1234`)
5. **Entropy estimation** – Approximates randomness using Shannon entropy

Each factor contributes to an overall **score (0–100)** and a **strength verdict**.

---

## 🚀 Usage

### Run with password as an argument

```bash
python checker.py "MyP@ssw0rd!"
```

### Run interactively

```bash
python checker.py
```

You will be prompted to enter a password for analysis.

---

## 📊 Example Output

```text
Password analysis:
Length: 12
Contains: lower upper digit special
Entropy (bits): 52.41
Score: 78 / 100
Verdict: Strong

Suggestions:
- Consider using a longer passphrase for even better security.
```

---

## 🧩 JSON Output (for automation)

```bash
python checker.py "MyP@ssw0rd!" --json
```

Example:

```json
{
  "password_length": 12,
  "has_lower": true,
  "has_upper": true,
  "has_digit": true,
  "has_special": true,
  "is_common": false,
  "entropy_bits": 52.41,
  "score": 78,
  "verdict": "Strong",
  "suggestions": []
}
```

---

## 🗂 Repository Structure

```text
Password-Strength-Checker/
├── checker.py           # Main CLI tool
├── README.md            # Project documentation
├── SECURITY.md          # Responsible usage policy
├── LICENSE              # MIT License
├── .gitignore
└── tests/
    └── test_checker.py  # Basic unit tests
```

---

## 🔒 Responsible Use

* ✅ Use only test passwords or your own passwords
* ❌ Do not use real user passwords
* ❌ Do not log or store passwords
* ✅ Intended for learning and defensive security analysis only

This tool does **not** perform brute-force attacks or password cracking.

---

## 🧪 Running Tests

```bash
pip install pytest
pytest -q
```

---

## 🛠 Future Improvements

* Add a passphrase generator
* Integrate breach checking using k-anonymity
* Add a simple web interface
* Add GitHub Actions for automated testing

---

## 📜 License

This project is licensed under the **MIT License**. See the `LICENSE` file for details.

---

## 👤 Author

**Tushar Kothyari**
Cybersecurity practitioner | Web Pentesting | Ethical Hacking

Learning security by building and breaking things responsibly.
