# Contributing to R0N Ingress

Thank you for your interest in contributing to R0N Ingress! This document provides guidelines and information for contributors.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment for everyone.

## Getting Started

### Prerequisites

- Rust 1.75.0 or later
- Git

### Setup

1. Fork the repository
2. Clone your fork:

   ```bash
   git clone https://github.com/YOUR_USERNAME/R0N-Ingress.git
   cd R0N-Ingress
   ```

3. Add the upstream remote:

   ```bash
   git remote add upstream https://github.com/R0N-Labs/R0N-Ingress.git
   ```

4. Build and test:

   ```bash
   cargo build
   cargo test
   ```

## Development Workflow

### Branch Naming

- `feature/` - New features
- `fix/` - Bug fixes
- `docs/` - Documentation changes
- `refactor/` - Code refactoring
- `test/` - Test additions or modifications

Example: `feature/mqtt-handler` or `fix/tcp-connection-leak`

### Making Changes

1. Create a new branch from `master`:

   ```bash
   git checkout master
   git pull upstream master
   git checkout -b feature/your-feature-name
   ```

2. Make your changes following our coding standards

3. Run tests and checks:

   ```bash
   cargo fmt --check
   cargo clippy -- -D warnings
   cargo test
   ```

4. Commit your changes with a descriptive message:

   ```bash
   git commit -m "feat: add MQTT topic routing support"
   ```

### Commit Message Format

We follow [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` - A new feature
- `fix:` - A bug fix
- `docs:` - Documentation only changes
- `style:` - Formatting, missing semicolons, etc.
- `refactor:` - Code change that neither fixes a bug nor adds a feature
- `perf:` - Performance improvement
- `test:` - Adding or updating tests
- `chore:` - Build process or auxiliary tool changes

Example:

```text
feat(mqtt): add topic-based routing

- Implement TopicTree data structure
- Add route matching for MQTT topics
- Support wildcards (+ and #)

Closes #123
```

## Coding Standards

### Rust Style

- Follow [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- Use `rustfmt` with our configuration (see `rustfmt.toml`)
- Address all `clippy` warnings
- Write documentation for public APIs

### Documentation

- All public items must have documentation comments
- Use `///` for item documentation
- Use `//!` for module-level documentation
- Include examples where helpful

### Testing

- Write unit tests for new functionality
- Integration tests go in `tests/`
- Aim for good test coverage on critical paths
- Tests should be deterministic and fast

### Module Development

When creating new modules:

1. Implement the `ModuleContract` trait
2. Provide a `ModuleManifest` with capabilities
3. Add configuration schema
4. Include unit and integration tests
5. Document the module in the SRS if applicable

## Pull Request Process

1. Update documentation for any changed functionality
2. Add or update tests as needed
3. Ensure all CI checks pass
4. Request review from maintainers
5. Address review feedback
6. Squash commits if requested

### PR Title Format

Follow the same format as commit messages:

```text
feat(router): implement SNI-based routing
```

### PR Description Template

```markdown
## Summary

Brief description of the changes.

## Changes

- Bullet point list of changes
- Include any breaking changes

## Testing

Describe how you tested the changes.

## Related Issues

Closes #123
```

## Module Control Contract

All ingress modules must implement the Module Control Contract:

```rust
pub trait ModuleContract {
    fn init(&mut self, config: ModuleConfig) -> Result<(), ModuleError>;
    fn start(&mut self) -> Result<(), ModuleError>;
    fn stop(&mut self) -> Result<(), ModuleError>;
    fn reload(&mut self, config: ModuleConfig) -> Result<(), ModuleError>;
    fn status(&self) -> ModuleStatus;
    fn metrics(&self) -> MetricsPayload;
    fn capabilities(&self) -> ModuleCapabilities;
    
    // Lifecycle control (optional, default returns error)
    fn pause(&mut self) -> Result<(), ModuleError>;
    fn resume(&mut self) -> Result<(), ModuleError>;
    fn contract_version(&self) -> ContractVersion;
}
```

See the SRS document (Section 3.8) for detailed contract requirements.

## Reporting Issues

### Bug Reports

Include:

- R0N Ingress version
- Operating system and version
- Steps to reproduce
- Expected behavior
- Actual behavior
- Relevant logs or error messages

### Feature Requests

Include:

- Use case description
- Proposed solution (if any)
- Alternatives considered

## Security

If you discover a security vulnerability, please do NOT open a public issue. Instead, email <security@r0n.example> with details.

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0, the same license as the project.

## Questions?

Feel free to open a discussion or reach out to the maintainers.

Thank you for contributing! 🚀
