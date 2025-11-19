```mermaid
graph B
    A[Original Nulls: 168] --> B[Skeeterspit.bin: 0<br/>(100% reduction)]
    A --> C[c_B_f.bin: 0<br/>(100% reduction)]
    A --> D[Imon.bin: 0<br/>(100% reduction)]
    A --> E[Prima_vulnus.bin: 0<br/>(100% reduction)]
    A --> F[RednefeD_swodniW.bin: 0<br/>(100% reduction)]
    A --> G[Sysutil.bin: 0<br/>(100% reduction)]
    A --> H[EHS.bin: 0<br/>(100% reduction)]
    A --> I[Ouroboros_core.bin: 0<br/>(100% reduction)]
    A --> J[Cutyourmeat-static.bin: 4<br/>(81% reduction)]
    A --> K[Cheapsuit.bin: 36<br/>(52% reduction)]
    
    B -.-> N{Final Nulls: 40}
    C -.-> N
    D -.-> N
    E -.-> N
    F -.-> N
    G -.-> N
    H -.-> N
    I -.-> N
    J -.-> N
    K -.-> N
    
    N -.-> O{Overall: 76% reduction<br/>(168 → 40 nulls)}
    
    style A fill:#ffcdd2
    style N fill:#f8f9fa
    style O fill:#d1ecf1
    style B fill:#d4edda
    style C fill:#d4edda
    style D fill:#d4edda
    style E fill:#d4edda
    style F fill:#d4edda
    style G fill:#d4edda
    style H fill:#d4edda
    style I fill:#d4edda
    style J fill:#fff3cd
    style K fill:#f8d7da
```