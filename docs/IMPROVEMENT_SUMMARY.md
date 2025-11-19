# KodeCD SAST - Improvement Plan Summary

**Status**: 📋 PLANNING PHASE
**Priority**: 🔴 CRITICAL - Core Accuracy Issues
**Timeline**: 8-12 weeks (2-3 developers)
**Effort**: 650-900 hours total

---

## The Core Problem

The code review identified that **the current implementation will produce inaccurate results** due to:

1. 🔴 **Broken Taint Analysis** - Operates on string labels instead of AST nodes (CRITICAL BUG)
2. 🔴 **Incomplete CFG** - Missing 80% of control flow constructs
3. 🟠 **Shallow AST** - 40% of language constructs map to generic "Other" node
4. 🟠 **Missing Symbol Resolution** - Can't track variable types or usages

**Bottom Line**: The engine will have high false positives/negatives and won't scale.

---

## The Solution: 3-Phase Plan

### Phase 1: Foundation (Weeks 1-4) - CRITICAL PATH

**Goal**: Fix core accuracy issues that block everything else

| Task | Priority | Effort | Impact |
|------|----------|--------|--------|
| **1. Rich AST Classification** | 🔴 CRITICAL | 40-60h | Unlocks all analysis |
| Expand `AstNodeKind` from ~20 to 50+ variants | | | |
| Add switch, try/catch, do-while, break/continue, etc. | | | |
|  |  |  |  |
| **2. Symbol Table** | 🔴 CRITICAL | 30-40h | Enables variable tracking |
| Track declarations AND usages | | | |
| Implement scope resolution | | | |
| Link symbols to types | | | |
|  |  |  |  |
| **3. Complete CFG** | 🔴 CRITICAL | 60-80h | Fixes control flow model |
| Add switch/case branches | | | |
| Add try/catch exception flow | | | |
| Add break/continue jump edges | | | |
| Add do-while, return, ternary | | | |
|  |  |  |  |
| **4. REWRITE Taint Analysis** | 🔴 CRITICAL | 80-100h | HIGHEST PRIORITY |
| Change `transfer()` to work with AST nodes | | | |
| Implement `evaluate_expression()` for all types | | | |
| Correctly handle assignments, calls, members | | | |
| Track sanitization properly | | | |
|  |  |  |  |
| **5. Remove CFG Cloning** | 🟠 HIGH | 20-30h | 50-80% speedup |
| Add lifetimes to `TransferFunction` trait | | | |
| Remove `'static` bound | | | |
| DELETE `clone_cfg()` entirely | | | |

**Phase 1 Total**: 230-310 hours (6-8 weeks for 1 dev, 3-4 weeks for 2 devs)

---

### Phase 2: Advanced Analysis (Weeks 5-8)

**Goal**: Add type inference and improve query accuracy

| Task | Effort | Dependencies |
|------|--------|--------------|
| **6. Type Inference System** | 60-80h | Symbol Table (Task 2) |
| Design minimal type system (6 base types) | | |
| Implement constraint collection | | |
| Solve constraints (unification) | | |
| Propagate types through expressions | | |
|  |  |  |
| **7. Accurate Call Graph** | 40-50h | Symbol Table, Type Inference |
| Use type info to resolve method calls | | |
| Handle polymorphism (multiple targets) | | |
|  |  |  |
| **8. Query Executor Refactor** | 40-50h | Symbol Table, Taint Analysis |
| Use AST instead of string matching | | |
| Deep property access evaluation | | |
| Link taint results to AST nodes | | |
|  |  |  |
| **9. Complete SARIF** | 15-20h | None |
| Add ruleId, tool.driver.rules | | |
| Add codeFlows for taint paths | | |

**Phase 2 Total**: 155-200 hours (4-5 weeks for 1 dev, 2-3 weeks for 2 devs)

---

### Phase 3: Scale & Polish (Weeks 9-12)

**Goal**: Performance, testing, documentation

| Task | Effort |
|------|--------|
| **10. Performance Optimization** | 40-60h |
| Profile with large codebases | |
| Optimize hot paths | |
| Parallel processing | |
|  |  |
| **11. Testing & Validation** | 40-60h |
| Expand to 500+ test cases | |
| CVE-based tests | |
| Accuracy benchmarking | |
|  |  |
| **12. Documentation** | 20-30h |
| Architecture docs | |
| Query writing guide | |
| API documentation | |

**Phase 3 Total**: 100-150 hours (3-4 weeks for 1 dev)

---

## Critical Path (Must Do First)

```
1. Expand AST (Task 1)
   ↓
2. Build Symbol Table (Task 2)
   ↓
3. Complete CFG (Task 3)
   ↓
4. REWRITE Taint Analysis (Task 4) ← BLOCKS EVERYTHING
   ↓
5. Remove CFG Cloning (Task 5)
```

**These 5 tasks MUST be done before anything else works correctly.**

---

## Quick Wins (Can Do Independently)

These can be done in parallel or by different developers:

- ✅ Remove global node ID counter (Task 1.1.3) - 10-15h → 20-40% parse speedup
- ✅ Use tree-sitter named fields (Task 1.1.2) - 20-30h → More reliable parsing
- ✅ Complete SARIF output (Task 9) - 15-20h → Better tool integration
- ✅ Stack overflow protection (Task 1.1.4) - 8-12h → Security hardening

---

## Resource Requirements

### Option A: 1 Senior Developer (Compiler/Analysis Expert)
- **Timeline**: 16-20 weeks (4-5 months)
- **Cost**: ~$80K-120K (contractor) or 4-5 months salary
- **Risk**: Single point of failure, longer timeline

### Option B: 2 Mid-Senior Developers
- **Timeline**: 8-12 weeks (2-3 months)
- **Division**:
  - Developer 1: Parser + AST (Tasks 1-2)
  - Developer 2: Analyzer + CFG (Tasks 3-5)
- **Cost**: ~$100K-160K (contractors)
- **Risk**: Lower, faster completion

### Option C: 3 Developers
- **Timeline**: 6-8 weeks (1.5-2 months)
- **Division**:
  - Developer 1: Parser (Task 1)
  - Developer 2: Analyzer (Tasks 2-5)
  - Developer 3: Query/Reporter (Tasks 8-9)
- **Cost**: ~$120K-180K (contractors)
- **Risk**: Lowest, fastest completion

**Recommended**: **Option B** (2 developers for 8-12 weeks)

---

## Expected Outcomes

### After Phase 1 (Week 4):
- ✅ Taint analysis produces **accurate results**
- ✅ CFG models **all control flow**
- ✅ AST captures **95%+ of language semantics**
- ✅ **50-80% performance improvement** (no cloning)
- ✅ Test suite: 500+ cases, all passing

### After Phase 2 (Week 8):
- ✅ Type-aware analysis (method resolution, polymorphism)
- ✅ Accurate call graph construction
- ✅ Query language works reliably
- ✅ False positive rate: **<5%** (down from ~20-30%)
- ✅ False negative rate: **<10%** (down from ~30-40%)

### After Phase 3 (Week 12):
- ✅ Production-ready performance (100K+ LOC files)
- ✅ Comprehensive test coverage (500+ cases)
- ✅ Complete documentation
- ✅ **Competitive with Semgrep/Snyk accuracy**
- ✅ **Superior performance** (local, no cloud)

---

## ROI Analysis

### Current State (Without Fixes):
- ❌ High false positive rate → Users ignore findings
- ❌ High false negative rate → Misses real vulnerabilities
- ❌ Poor performance → Can't scale to large repos
- ❌ Inaccurate taint analysis → Core feature broken
- **Business Impact**: Not production-ready, can't compete with Snyk/Semgrep

### After Phase 1 (Investment: ~$50K-80K, 4 weeks):
- ✅ Core accuracy fixed → Usable for real security testing
- ✅ Performance improved → Handles medium projects (10K-50K LOC)
- ✅ Taint analysis works → Core value proposition delivered
- **Business Impact**: MVP-ready, can acquire early adopters

### After Phase 2 (Investment: ~$100K-160K, 8 weeks):
- ✅ Advanced analysis → Competitive with Semgrep
- ✅ Low false positive rate → Users trust results
- ✅ Type-aware → Handles OOP code correctly
- **Business Impact**: Production-ready, can compete for enterprise customers

### After Phase 3 (Investment: ~$120K-200K, 12 weeks):
- ✅ Enterprise-scale performance → Handles large repos (100K+ LOC)
- ✅ Complete documentation → Easy adoption
- ✅ Accuracy benchmarked → Marketing ammunition
- **Business Impact**: Enterprise-ready, premium pricing justified

---

## Risk Mitigation

### Technical Risks

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Taint rewrite breaks everything | High | Critical | Implement new version alongside old, A/B test |
| Timeline overruns | Medium | High | Cut low-priority features (Phase 3) |
| Type inference too complex | Medium | Medium | Start simple, expand gradually |
| Performance regressions | Low | Medium | Benchmark before/after each change |

### Business Risks

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Competitors release similar features | Medium | High | Focus on Phase 1 (unique accuracy) |
| Budget constraints | Low | High | Phase 1 provides MVP, can ship after 4 weeks |
| Can't hire qualified developers | Medium | Critical | Consider consulting firms specializing in compilers |

---

## Decision Framework

### Should We Do This?

**YES, if you want to:**
- ✅ Compete with Snyk/Semgrep on accuracy
- ✅ Target enterprise customers (they care about false positives)
- ✅ Scale to large codebases (100K+ LOC)
- ✅ Have defensible technical moat

**NO, if you want to:**
- ❌ Ship "good enough" for small projects only
- ❌ Focus on breadth over depth (more languages, less accuracy)
- ❌ Pivot away from SAST entirely

### Minimum Viable Scope

**If budget is limited**, you can ship after **Phase 1 only** (4 weeks, $50K-80K):
- ✅ Core taint analysis works (main value prop)
- ✅ CFG handles most code patterns
- ✅ Performance is acceptable
- ⚠️ Missing advanced features (type inference, perfect call graph)
- ⚠️ Still has some rough edges

**This gets you to "production-ready" but not "best-in-class".**

---

## Implementation Timeline

### Week 1-2: AST & Symbol Table
- Days 1-7: Expand AST classification (Task 1)
- Days 8-14: Build symbol table (Task 2)

### Week 3-4: CFG & Taint Analysis
- Days 15-21: Complete CFG construction (Task 3)
- Days 22-28: Start taint analysis rewrite (Task 4)

### Week 5-6: Taint Analysis Completion
- Days 29-35: Finish taint analysis rewrite (Task 4)
- Days 36-42: Remove CFG cloning (Task 5)

### Week 7-8: Advanced Features
- Days 43-49: Type inference (Task 6)
- Days 50-56: Call graph + Query executor (Tasks 7-8)

### Week 9-10: Polish
- Days 57-63: Performance optimization (Task 10)
- Days 64-70: Testing & validation (Task 11)

### Week 11-12: Documentation & Launch
- Days 71-77: Documentation (Task 12)
- Days 78-84: Final testing, launch prep

---

## Success Metrics

### Technical Metrics
- **False Positive Rate**: < 5% (currently unknown, likely 20-30%)
- **False Negative Rate**: < 10% (currently unknown, likely 30-40%)
- **Parse Speed**: 10-50ms per file (1000+ LOC)
- **Taint Analysis Speed**: < 1s per function
- **Memory Usage**: < 500MB for 100K LOC project

### Business Metrics
- **Customer Satisfaction**: NPS > 40
- **Feature Adoption**: 80%+ of users run taint analysis
- **Performance Competitiveness**: 2-5x faster than Semgrep
- **Accuracy Competitiveness**: Match or beat Snyk false positive rate

---

## Next Steps

### Immediate (This Week):
1. **Review this plan with stakeholders**
2. **Decide on scope** (Phase 1 only? All 3 phases?)
3. **Allocate budget** ($50K-200K depending on scope)
4. **Post job descriptions** (2 compiler/analysis engineers)

### Week 1:
1. **Hire developers** (or assign internal team)
2. **Set up project tracking** (GitHub Projects, Jira)
3. **Create refactor branch** (`feature/core-analysis-accuracy`)
4. **Establish performance baselines** (benchmark current state)

### Week 2:
1. **Begin Phase 1, Task 1** (AST Classification)
2. **Daily standups** to track progress
3. **Weekly demos** to stakeholders

---

## Conclusion

The code review revealed **critical accuracy issues** that must be fixed for KodeCD SAST to be production-ready. The good news: the architecture is sound, and the issues are fixable.

**Recommended path forward**:
1. **Commit to Phase 1** (4 weeks, $50K-80K, 2 developers)
2. **Ship MVP after Phase 1** (get early adopters, validate approach)
3. **Evaluate success**, then decide on Phase 2+3

**Alternative**: If resources are constrained, focus on **Task 4 only** (taint analysis rewrite, 2 weeks, 1 developer) as the bare minimum.

**Questions?** Let's discuss resource allocation, timeline, or technical approach.

---

**Status**: 📋 **AWAITING DECISION**
**Next**: Leadership review → Budget approval → Hiring → Phase 1 kickoff
