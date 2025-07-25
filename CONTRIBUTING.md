# Contributing to PWN AI Analyzer

We welcome contributions from the CTF community! This document provides guidelines for contributing to the project.

## Getting Started

### Development Environment Setup

1. **Fork and Clone**
   ```bash
   git fork https://github.com/iNeenah/PwnCtf.git
   git clone https://github.com/your-username/PwnCtf.git
   cd PwnCtf
   ```

2. **Install Development Dependencies**
   ```bash
   pip install -r requirements-dev.txt
   pre-commit install
   ```

3. **Verify Installation**
   ```bash
   python -m pytest tests/
   python demo_simple_pwn_ai.py
   ```

## Types of Contributions

### 1. New Techniques
Add techniques from CTF writeups or your own research.

**Process:**
1. Implement technique in `advanced_pwn_solver.py`
2. Add detection patterns in `detect_mindcrafters_challenge_type()`
3. Update technique mapping in `apply_mindcrafters_technique()`
4. Add tests and documentation
5. Create example challenge

**Example:**
```python
def new_technique_exploit(self):
    """
    New technique description
    Source: CTF Name - Challenge Name
    """
    # Implementation here
    return payload
```

### 2. Bug Fixes
Report and fix bugs in existing functionality.

**Process:**
1. Create issue describing the bug
2. Write test that reproduces the bug
3. Fix the bug
4. Ensure test passes
5. Submit pull request

### 3. Documentation
Improve documentation, examples, and guides.

**Areas:**
- API documentation
- Technique explanations
- Usage examples
- Installation guides

### 4. Testing
Add tests for existing functionality.

**Types:**
- Unit tests for individual functions
- Integration tests for complete workflows
- Performance tests for analysis speed
- Security tests for exploit generation

## Code Standards

### Python Style
- **PEP 8** compliance
- **Type hints** for function signatures
- **Docstrings** for all public functions
- **Comments** for complex logic

**Example:**
```python
def analyze_binary(self, binary_path: str) -> Dict[str, Any]:
    """
    Analyze binary file for vulnerabilities.
    
    Args:
        binary_path: Path to binary file
        
    Returns:
        Dictionary containing analysis results
        
    Raises:
        AnalysisError: If analysis fails
    """
    # Implementation here
    pass
```

### Code Quality Tools
- **Black** - Code formatting
- **Flake8** - Linting
- **MyPy** - Type checking
- **Pytest** - Testing

**Run Quality Checks:**
```bash
black .
flake8 .
mypy .
pytest tests/
```

## Testing Guidelines

### Test Structure
```
tests/
├── unit/           # Unit tests
├── integration/    # Integration tests
├── fixtures/       # Test data
└── conftest.py     # Pytest configuration
```

### Writing Tests
```python
import pytest
from pwn_ai_analyzer import PWNAIAnalyzer

class TestPWNAIAnalyzer:
    def test_analyze_single_file(self):
        analyzer = PWNAIAnalyzer()
        result = analyzer.analyze_single_file("tests/fixtures/test_binary")
        assert result is not None
        
    def test_flag_detection(self):
        analyzer = PWNAIAnalyzer()
        flags = analyzer.search_flags_in_text("flag{test_flag}")
        assert len(flags) == 1
        assert flags[0] == "flag{test_flag}"
```

### Test Coverage
Maintain minimum 80% test coverage:
```bash
pytest --cov=pwn_ai_analyzer --cov-report=html tests/
```

## Documentation Standards

### Code Documentation
- **Docstrings** for all public functions
- **Type hints** for parameters and returns
- **Examples** in docstrings when helpful

### User Documentation
- **Clear explanations** of functionality
- **Code examples** for usage
- **Screenshots** for web interface features
- **Troubleshooting** sections

### Technique Documentation
When adding new techniques, include:
- **Source** - Original writeup or research
- **Problem description** - What vulnerability it exploits
- **Solution approach** - How the technique works
- **Implementation details** - Code explanation
- **Usage examples** - How to apply the technique

## Pull Request Process

### Before Submitting
1. **Run tests** - Ensure all tests pass
2. **Check code quality** - Run linting and formatting
3. **Update documentation** - Add/update relevant docs
4. **Test manually** - Verify functionality works
5. **Write clear commit messages**

### PR Template
```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Performance improvement

## Testing
- [ ] Tests pass locally
- [ ] New tests added for new functionality
- [ ] Manual testing completed

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] No breaking changes (or documented)
```

### Review Process
1. **Automated checks** - CI/CD pipeline runs
2. **Code review** - Maintainer reviews code
3. **Testing** - Functionality verified
4. **Merge** - Changes integrated

## Adding New CTF Techniques

### Research Process
1. **Find writeups** from top CTF teams
2. **Analyze techniques** used in solutions
3. **Identify patterns** that can be automated
4. **Extract key insights** for implementation

### Implementation Steps
1. **Create technique function** in appropriate module
2. **Add detection logic** for automatic application
3. **Write comprehensive tests** with example challenges
4. **Document technique** with source attribution
5. **Add to technique registry**

### Example Implementation
```python
def new_ctf_technique(self, target_binary: str) -> bytes:
    """
    Implement technique from [CTF Name] - [Challenge Name]
    
    Source: https://writeup-url.com
    Technique: Brief description of what it does
    
    Args:
        target_binary: Path to target binary
        
    Returns:
        Exploitation payload
    """
    # Step 1: Analysis
    analysis = self.analyze_target(target_binary)
    
    # Step 2: Payload construction
    payload = self.build_payload(analysis)
    
    # Step 3: Validation
    if self.validate_payload(payload):
        return payload
    
    return None
```

## Community Guidelines

### Communication
- **Be respectful** and professional
- **Be constructive** in feedback
- **Be patient** with new contributors
- **Be inclusive** and welcoming

### Attribution
- **Credit sources** for techniques and ideas
- **Acknowledge contributors** in documentation
- **Respect licenses** of referenced work
- **Follow ethical guidelines** for security research

### Security Considerations
- **Responsible disclosure** for vulnerabilities
- **Educational purpose** - tools for learning
- **No malicious use** - ethical hacking only
- **Legal compliance** - follow applicable laws

## Release Process

### Version Numbering
- **Major** (X.0.0) - Breaking changes
- **Minor** (0.X.0) - New features, backward compatible
- **Patch** (0.0.X) - Bug fixes

### Release Checklist
1. **Update version** in `setup.py`
2. **Update CHANGELOG.md** with new features
3. **Run full test suite** 
4. **Update documentation**
5. **Create release tag**
6. **Publish to PyPI** (if applicable)

## Getting Help

### Resources
- **Documentation** - Check `docs/` directory
- **Examples** - See `examples/` for usage patterns
- **Tests** - Look at test files for usage examples
- **Issues** - Search existing issues for solutions

### Contact
- **GitHub Issues** - For bugs and feature requests
- **GitHub Discussions** - For questions and ideas
- **Email** - For security-related issues

## Recognition

Contributors will be recognized in:
- **README.md** - Contributors section
- **CHANGELOG.md** - Feature attribution
- **Documentation** - Technique attribution
- **Release notes** - Major contribution highlights

Thank you for contributing to PWN AI Analyzer!