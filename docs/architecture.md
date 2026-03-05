# Architecture Diagram

```mermaid
flowchart LR
    A[Repository] --> B[AST parser]
    B --> C[Static scanner]
    C --> D[LLM reasoning]
    D --> E[Report generator]
```
