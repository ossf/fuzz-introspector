# Contributing to Fuzz Introspector

We're glad you're interested in contributing to Fuzz Introspector! This document explains how to get involved, whether you're fixing a bug, improving documentation, or adding a new feature.

Fuzz Introspector is a project under the [OpenSSF Security Tooling Working Group](https://github.com/ossf/wg-security-tooling), a collaborative effort to improve the security of open source software. We welcome contributions from everyone.

## Code of Conduct

Before contributing, please read and follow our [Code of Conduct](https://github.com/ossf/fuzz-introspector/blob/main/CODE_OF_CONDUCT.md). We are committed to providing a welcoming and respectful environment for all contributors.

## Getting Started

### Prerequisites

- Python 3.11
- Git

### Setting Up Your Development Environment

1. **Fork the repository** on GitHub to your own account.
2. **Clone your fork** to your local machine:
   ```bash
   git clone https://github.com/<your-username>/fuzz-introspector.git
   cd fuzz-introspector
   ```
3. **Create a virtual environment** and activate it:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```
4. **Install dependencies** as described in the [documentation](https://fuzz-introspector.readthedocs.io).

### Running the CI Checks Locally

Before opening a pull request, run the linting and API tests locally:

```bash
bash ci_checks.sh
```

> **Note:** Activate your virtual environment before running this script, as it does not activate it automatically.

## Ways to Contribute

- **Bug fixes**: Found something broken? Open an issue and/or submit a fix.
- **New features**: Have an idea? Open an issue first to discuss it before writing code.
- **Documentation**: Improve the [docs](https://fuzz-introspector.readthedocs.io), fix typos, or clarify explanations.
- **Tests**: Add or improve tests to increase coverage and reliability.
- **Bug reports**: Report issues you encounter with clear reproduction steps.

## Steps to Contribute

1. **Find or create an issue** — Check the [issue tracker](https://github.com/ossf/fuzz-introspector/issues) for something you'd like to work on. For new ideas, open an issue first.
2. **Claim the issue** — Leave a comment stating your intent to work on it so others know it's being addressed.
3. **Create a branch** — Use a descriptive branch name:
   ```bash
   git checkout -b fix/issue-description
   ```
4. **Make your changes** — Keep changes focused and write tests for new functionality where applicable.
5. **Run CI checks** — Make sure `ci_checks.sh` passes before committing.
6. **Commit with a sign-off** — All commits must include a [Developer Certificate of Origin (DCO)](https://developercertificate.org/) sign-off line:
   ```bash
   git commit -s -m "fix: describe your change here"
   ```
   The `-s` flag adds the required `Signed-off-by: Your Name <your@email.com>` line automatically.
7. **Push your branch** and open a pull request against the `main` branch.
8. **Respond to review feedback** — Maintainers may request changes; please respond promptly.

## Commit Message Guidelines

Follow the [Conventional Commits](https://www.conventionalcommits.org/) format:

```
<type>: <short description>

[optional body]

Signed-off-by: Your Name <your@email.com>
```

Common types: `fix`, `feat`, `docs`, `test`, `refactor`, `chore`.

## Community & Discussion

If you'd like to get involved in the broader fuzzing community or discuss ideas before opening an issue, join the **[OpenSSF Security Tooling Working Group](https://github.com/ossf/wg-security-tooling)** meetings where Fuzz Introspector is regularly discussed.

## Additional Resources

- [Full documentation](https://fuzz-introspector.readthedocs.io)
- [Architecture overview](https://github.com/ossf/fuzz-introspector/blob/main/doc/Architecture.md)
- [OpenSSF Security Tooling WG](https://github.com/ossf/wg-security-tooling)
- [GitHub Pull Requests guide](https://docs.github.com/en/pull-requests)

We appreciate every contribution, big or small. Thank you for helping make open source software more secure!
