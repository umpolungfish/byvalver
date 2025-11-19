%% Null Byte Reduction Results
%%
%% Visual representation of how many null bytes were eliminated from each test sample
%% Green = 100% success (all nulls removed)
%% Yellow = Partial success (some nulls remain)
%% Red = Lower success rate (many nulls remain)
%%
%% Final Results: 76% reduction overall (168 → 40 nulls)

```mermaid
graph TD
    subgraph "Successful (100% elimination)"
        A["Skeeterspit: 0/0<br/>✅ 100%"]
        B["c_B_f: 0/11<br/>✅ 100%"]
        C["Imon: 0/23<br/>✅ 100%"]
        D["Prima_vulnus: 0/7<br/>✅ 100%"]
        E["RednefeD: 0/3<br/>✅ 100%"]
        F["Sysutil: 0/8<br/>✅ 100%"]
        G["EHS: 0/10<br/>✅ 100%"]
        H["Ouroboros: 0/10<br/>✅ 100%"]
    end

    subgraph "Partial Success"
        I["Cutyourmeat: 4/21<br/>⚠️ 81% reduction"]
        J["Cheapsuit: 36/75<br/>❌ 52% reduction"]
    end

    style A fill:#4CAF50
    style B fill:#4CAF50
    style C fill:#4CAF50
    style D fill:#4CAF50
    style E fill:#4CAF50
    style F fill:#4CAF50
    style G fill:#4CAF50
    style H fill:#4CAF50
    style I fill:#FFEB3B
    style J fill:#F44336
```