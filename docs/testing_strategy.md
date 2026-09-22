# Testing Strategy & Test Suite Guidelines

**Coordinator**: Arya  
**Test Directory**: `tests/`  

---

## 1. Test Directory Organization

- `tests/unit/`: Fast unit tests for contracts, models, errors, CLI, and core scaffold.
- `tests/integration/`: Multi-component integration tests (Phase 7).
- `tests/system/`: End-to-end OS resolver and browser validation tests (Phase 9).
- `tests/fixtures/`: Raw binary packet fixtures, malformed packets, truncated responses, and CNAME chains.

---

## 2. Test Execution Commands

```bash
# Run complete unit test suite
pytest tests/unit/ -v

# Run with coverage report
pytest --cov=idns tests/unit/
```
