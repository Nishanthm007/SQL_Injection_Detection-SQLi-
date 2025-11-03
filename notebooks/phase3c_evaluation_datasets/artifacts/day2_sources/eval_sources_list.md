# Phase 3C: Evaluation Data Sources List

**Document Version:** v1.0  
**Date:** November 2, 2025  
**Purpose:** Comprehensive list of data sources for evaluation dataset construction

---

## 1. Novel Attack Test Set Sources

### 1.1 Exploit Databases

**Exploit-DB (exploit-db.com)**
- Type: Public exploit database
- Access: Web scraping / API
- Expected Volume: 5,000+ SQLi exploits
- Focus: Recent CVE-based exploits (2024-2025)
- Legal Status: Public domain
- Priority: HIGH
- Collection: Filter by SQL injection category, date range post-2024

**CVE Database (National Vulnerability Database)**
- Type: Government vulnerability database
- Access: NVD REST API (https://nvd.nist.gov/developers)
- Expected Volume: 500-1,000 CVEs
- Focus: SQL injection vulnerabilities (CWE-89)
- Legal Status: Public domain
- Priority: HIGH
- Collection: API query for CWE-89, published 2024-2025

### 1.2 Payload Repositories

**PayloadsAllTheThings (GitHub)**
- URL: https://github.com/swisskyrepo/PayloadsAllTheThings
- Type: Community payload repository
- Access: Git clone
- Expected Volume: 3,000+ payloads
- Focus: SQL injection section, novel obfuscations
- Legal Status: MIT License (Public)
- Priority: HIGH
- Collection: Clone repo, extract SQL injection payloads

**SQL Injection Payload List (GitHub: payloadbox)**
- URL: https://github.com/payloadbox/sql-injection-payload-list
- Type: Curated payload collection
- Access: Git clone
- Expected Volume: 4,000+ payloads
- Focus: Time-based, union-based, error-based attacks
- Legal Status: MIT License (Public)
- Priority: HIGH
- Collection: Clone repo, parse payload files

### 1.3 Honeypot Sources

**Glastopf Honeypot**
- Type: Web application honeypot
- Access: Self-deployment
- Expected Volume: 1,000-3,000 captures
- Focus: Real-world SQLi attempts
- Legal Status: Self-deployed (no legal issues)
- Priority: MEDIUM
- Collection: Deploy for 2-4 weeks, extract attack logs
- Requirements: VPS instance, public IP exposure

**HoneyDB (honeydb.io)**
- Type: Honeypot data aggregator
- Access: API (requires registration)
- Expected Volume: 2,000-5,000 samples
- Focus: SQLi attack patterns from global sensors
- Legal Status: Public (terms of service apply)
- Priority: MEDIUM
- Collection: Register account, API access, filter SQLi events

---

## 2. Adversarial Evaluation Suite Sources

### 2.1 Training Platforms

**OWASP WebGoat**
- URL: https://owasp.org/www-project-webgoat/
- Type: Vulnerable web application for training
- Access: Download and deploy locally
- Expected Volume: ~500 documented SQLi variants
- Focus: Educational attack examples with obfuscations
- Legal Status: Open source (LGPL)
- Priority: HIGH
- Collection: Extract SQL injection lesson payloads

**PortSwigger Web Security Academy**
- URL: https://portswigger.net/web-security/sql-injection
- Type: Free online security training
- Access: Free account registration
- Expected Volume: ~1,000 lab payloads
- Focus: Advanced SQLi techniques, WAF bypasses
- Legal Status: Free access (terms apply)
- Priority: HIGH
- Collection: Complete labs, document payloads

---

## 3. Production Benign Complex Queries Sources

### 3.1 Community & Public Queries

**Stack Overflow SQL Queries**
- URL: https://stackoverflow.com/questions/tagged/sql
- Type: Q&A community
- Access: Web scraping (public content)
- Expected Volume: 10,000+ queries
- Focus: Complex analytic queries, troubleshooting examples
- Legal Status: CC BY-SA license (attribution required)
- Priority: MEDIUM
- Collection: Scrape highly-voted SQL questions, sanitize
- Sanitization: Remove table/column names, hash identifiers

**GitHub SQL Files Search**
- URL: https://github.com/search
- Type: Code repository
- Access: GitHub Search API
- Expected Volume: 20,000+ SQL files
- Focus: Production-like queries from open-source projects
- Legal Status: Various open-source licenses
- Priority: HIGH
- Collection: Search for .sql files, filter by stars/activity
- Sanitization: Remove PII, hash sensitive identifiers

### 3.2 ORM Framework Sources

**Django ORM Documentation**
- URL: https://docs.djangoproject.com/en/stable/topics/db/queries/
- Type: Framework documentation
- Access: Public documentation
- Expected Volume: ~1,000 query patterns
- Focus: ORM-generated SQL patterns
- Legal Status: BSD License
- Priority: MEDIUM
- Collection: Extract examples, generate variants

**SQLAlchemy Query Examples**
- URL: https://docs.sqlalchemy.org/
- Type: Framework documentation
- Access: Public documentation
- Expected Volume: ~1,000 query patterns
- Focus: ORM query patterns, complex joins
- Legal Status: MIT License
- Priority: MEDIUM
- Collection: Documentation examples, community recipes

### 3.3 Analytics & BI Sources

**DBT Project Repositories**
- URL: https://github.com/search?q=dbt+project
- Type: Data transformation projects
- Access: GitHub Search API
- Expected Volume: 5,000+ analytical queries
- Focus: Complex transformations, CTEs, window functions
- Legal Status: Various open-source licenses
- Priority: MEDIUM
- Collection: Search dbt projects, extract .sql models

---

## 4. Cross-Domain Test Set Sources

### 4.1 NoSQL Sources

**MongoDB Documentation**
- URL: https://docs.mongodb.com/
- Type: Database documentation
- Access: Public documentation
- Expected Volume: ~500 query examples
- Focus: Aggregation pipelines, injection attempts
- Legal Status: Public
- Priority: HIGH
- Collection: Extract query examples, create injection variants

### 4.2 GraphQL Sources

**GraphQL Public APIs**
- Type: Public API endpoints
- Access: Public GraphQL playgrounds
- Expected Volume: ~500 queries
- Focus: Nested queries, fragment usage
- Legal Status: Public APIs
- Priority: HIGH
- Collection: Query public endpoints, document patterns

### 4.3 Semantic Web Sources

**DBpedia SPARQL Endpoint**
- URL: https://dbpedia.org/sparql
- Type: Linked data query endpoint
- Access: Public SPARQL endpoint
- Expected Volume: ~1,000 queries
- Focus: RDF triple patterns, FILTER clauses
- Legal Status: CC BY-SA 3.0
- Priority: MEDIUM
- Collection: Query endpoint, extract common patterns

**Wikidata Query Service**
- URL: https://query.wikidata.org/
- Type: Knowledge base query service
- Access: Public SPARQL endpoint
- Expected Volume: ~1,000 queries
- Focus: Complex semantic queries
- Legal Status: CC0 (Public Domain)
- Priority: MEDIUM
- Collection: Browse example queries, extract patterns

---

## 5. Legal & Ethical Constraints

### 5.1 Public Data Usage Requirements

**Attribution:**
- CC-BY and CC-BY-SA: Include source attribution
- MIT, BSD: Include license in documentation
- Public domain / CC0: No restrictions

**Prohibited Actions:**
- NO commercial use without approval
- NO removal of attribution or license headers
- NO redistribution of datasets without original licenses

### 5.2 Production Log Usage - REQUIRES WRITTEN APPROVAL

**Approval Checklist:**
- [ ] Legal review by organization's counsel
- [ ] Data sharing agreement with partner organization
- [ ] Privacy impact assessment completed
- [ ] PII sanitization protocol approved
- [ ] Data retention/deletion policy established
- [ ] Security measures for data handling documented

**Sanitization Requirements:**
- Hash or remove: usernames, email addresses, IP addresses
- Tokenize: table names, column names, database names
- Remove: literal values containing potential PII
- Preserve: query structure, syntax patterns, complexity

### 5.3 Ethical Constraints

**Honeypot Deployment:**
- Deploy only on owned infrastructure
- Clearly mark honeypot data as non-production
- Do not use captured data outside of research scope

**Web Scraping:**
- Respect robots.txt directives
- Rate limit requests (avoid DDoS-like behavior)
- Use public APIs where available
- Attribute sources appropriately

---

## 6. Collection Timeline

**Week 1 (Days 3-4): Novel Attacks**
- Exploit-DB scraping
- CVE database API queries
- PayloadsAllTheThings clone
- SQL Injection Payload List clone

**Week 1 (Days 5-6): Adversarial Suite**
- OWASP WebGoat payload extraction
- PortSwigger Academy labs
- Seed payload selection

**Week 2 (Day 7): Production Benign**
- GitHub SQL file search
- Stack Overflow query scraping
- ORM documentation extraction

**Week 2 (Day 8): Cross-Domain**
- MongoDB documentation queries
- GraphQL API sampling
- SPARQL endpoint queries

**Honeypot Deployment (Parallel):**
- Deploy Glastopf by Day 1, collect through Day 10

---

## 7. Expected Dataset Sizes

| Target Dataset | Total Sources | Expected Samples (Raw) | After Filtering |
|----------------|---------------|------------------------|-----------------|
| Novel Attack Test Set | 7 sources | 15,000-25,000 | 1,500-5,000 |
| Adversarial Suite | 4 sources | 5,000-10,000 (seeds) | 2,000-4,000 |
| Production Benign | 10 sources | 40,000-50,000 | 5,000-10,000 |
| Cross-Domain | 5 sources | 3,500-5,000 | 1,800-3,000 |

**Total Raw Collection:** 60,000-90,000 samples  
**Total Filtered Evaluation Set:** 10,000-22,000 samples

---

## 8. Stakeholder Sign-Off

**Approval Status:**

| Item | Status | Approver | Date |
|------|--------|----------|------|
| Public source list approved | [ ] | _____________ | ______ |
| Legal compliance reviewed | [ ] | _____________ | ______ |
| Ethical constraints acknowledged | [ ] | _____________ | ______ |
| Infrastructure deployment approved | [ ] | _____________ | ______ |

**All sources approved and accessible:** [ ] YES / [ ] NO

---

**Document Status:** DRAFT - Awaiting Approval  
**Next Action:** Stakeholder review and sign-off  
**Proceed to Day 3:** Upon approval
