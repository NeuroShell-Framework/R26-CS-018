# Contributing to NeuroShell Core

Thank you for your interest in contributing to NeuroShell Core!

## Code of Conduct

- Be respectful and inclusive
- Provide constructive feedback
- Welcome newcomers and help them learn
- Focus on the best interests of the project

## Branch Naming Conventions

Use the following branch naming format:

| Type | Prefix | Example |
|------|--------|---------|
| Feature | `feature/` | `feature/add-user-service` |
| Bugfix | `fix/` | `fix/auth-error-handling` |
| Hotfix | `hotfix/` | `hotfix/security-patch` |
| Release | `release/` | `release/v1.0.0` |
| Docs | `docs/` | `docs/api-documentation` |
| Refactor | `refactor/` | `refactor/cleanup-models` |

## Commit Message Format

We follow [Conventional Commits](https://www.conventionalcommits.org/) specification.

### Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types

| Type | Description |
|------|-------------|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation |
| `style` | Code style (formatting) |
| `refactor` | Code refactoring |
| `test` | Tests |
| `chore` | Maintenance |
| `ci` | CI/CD |
| `perf` | Performance |
| `build` | Build system |

### Examples

```bash
feat(auth): add JWT token refresh endpoint

- Added /api/v1/auth/refresh endpoint
- Token expiry extended to 24 hours
- Added refresh token rotation

Closes #123
```

```bash
fix(error-handler): correct exception handling for validation errors

- Improved error message formatting
- Added request ID to error responses

Fixes #456
```

```bash
docs(readme): update API documentation

- Added new endpoint examples
- Improved troubleshooting section
```

```bash
ci(workflow): add security scanning to CI pipeline

- Added Bandit security scanner
- Added vulnerability scanning
```

## Pull Request Guidelines

### Before Submitting

1. **Run linting:**
```bash
poetry run ruff check .
poetry run black --check .
```

2. **Run tests:**
```bash
poetry run pytest -v
```

3. **Update documentation** if needed

4. **Keep commits atomic** - one feature per commit

### PR Description Template

```markdown
## Summary
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
Describe testing performed

## Checklist
- [ ] Code follows style guidelines
- [ ] Tests pass locally
- [ ] Documentation updated
- [ ] No breaking changes
```

### PR Size

- Keep PRs under 400 lines of code
- Split large changes into smaller PRs

## Code Review Expectations

### For Reviewers

- Review within 24-48 hours
- Provide constructive feedback
- Approve or request changes clearly
- Test changes locally when possible

### For Authors

- Respond to feedback promptly
- Make requested changes
- Keep discussions focused

## Coding Standards

### Python

- Use type hints
- Follow PEP 8
- Maximum line length: 100
- Use f-strings for formatting

### Naming

| Type | Convention | Example |
|------|-----------|---------|
| Functions | snake_case | `get_user_by_id` |
| Classes | PascalCase | `UserService` |
| Constants | SCREAMING_SNAKE | `MAX_RETRIES` |
| Variables | snake_case | `user_id` |

### Docstrings

```python
def function_name(param: str) -> dict:
    """Short description of what the function does.

    Longer description if needed.

    Args:
        param: Description of parameter

    Returns:
        Description of return value

    Raises:
        ValueError: When parameter is invalid
    """
```

## Git Workflow

```
main ───────────────────────────────────────────────────
  │
  │    feature/xxx ─────────────────────────┐
  │                                        │
  │    commit 1                           │
  │    commit 2                           │
  │                                     ▼
  │                              Pull Request
  │                                        │
  └──────────────────────────────────────────┘
```

## Questions?

- Open an issue for bugs or feature requests
- Use discussions for questions
- Contact the maintainers for security issues

## Acknowledgments

Thank you for contributing to NeuroShell Core!