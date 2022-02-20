# awesome-software-supply-chain-security [![Awesome](https://awesome.re/badge.svg)](https://awesome.re)

A compilation of resources in the software supply chain security domain, with emphasis on open source.

## About the categories

There is no prescribed taxonomy for this domain. This list will necessarily have some overlap with disciplines and categories such as DevSecOps and SCA. The [supply-chain-synthesis](https://github.com/AevaOnline/supply-chain-synthesis/) repo offers a long-form read on why that's the case, plus helpful pointers to understand and navigate it as it evolves.

For `awesome-software-supply-chain-security` we take the following high-level approach: different actors in the supply chain contribute **attestations** to the elements represented in the chain. In this process view, attestations are _emitted_, _augmented_ (e.g., during composition) and _verified_.

Using this lens we can identify a large group of "subjects" (dependencies), distinct categories of "facts" (licenses or vulnerabilities) and the specific role of identity, provenance and build systems. This is the rationale behind the current headings, which are expected to evolve with the domain.

## Dependency management

> This section includes: package management, library management, dependency management, vendored dependency management, by-hash searches, package, library and dependency naming, library behavior labeling, library publishing, registries and repositories, publishing gates and scans, dependency lifecycle.

* **TODO**: dereference the excellent starting point from [awesome-devsecops](https://github.com/TaptuIT/awesome-devsecops#dependency-management)
  * Possibly also the [containers](https://github.com/TaptuIT/awesome-devsecops#containers) section
  * Also the containers section of [awesome-static-analysis](https://github.com/analysis-tools-dev/static-analysis/#containers) and the [security](https://github.com/analysis-tools-dev/static-analysis/#securitysast) one
  * On containers, also [awesome-linux-containers](https://github.com/Friz-zy/awesome-linux-containers#security) and the `kubernetes` section in [awesome-cybersecurity-blueteam](https://github.com/fabacab/awesome-cybersecurity-blueteam#kubernetes)
* Online services that help understand what a specific dependency _is_ (usually feeding it a package identifier, such as `purl`, CPE or another form of `ecosystem:name:version`, or alternatively via hash):
  * [NSRL](https://www.nist.gov/itl/ssd/software-quality-group/national-software-reference-library-nsrl/about-nsrl/library-contents): hashes for [COTS software](https://www.nist.gov/itl/ssd/software-quality-group/national-software-reference-library-nsrl/about-nsrl/library-contents), well-integrated in tooling from [sleuthkit/hfind](http://manpages.ubuntu.com/manpages/bionic/man1/hfind.1.html) to [nsrllookup](https://github.com/rjhansen/nsrllookup)
  * A source that can be queried via a public API (HTTP and DNS!) and can be more open source-aware is [CIRCL hashlookup](https://www.circl.lu/services/hashlookup/)
  * [Repology](https://repology.org/) has legendary coverage for Linux packages across multiple distribution; its [repology-updater](https://github.com/repology/repology-updater) and other infrastructure pieces are open source. It provides an updater for [WikiData](https://github.com/repology/repology-wikidata-bot) which also has properties of interest for the supply chain security domain.
  * Tidelift's [libraries.io](https://libraries.io/) provides an [API](https://libraries.io/api) and supports over 30 package ecosystems
  * WhiteSource's [Unified Agent](https://whitesource.atlassian.net/wiki/spaces/WD/pages/1140852201/Getting+Started+with+the+Unified+Agent#Binary-and-Source-File-Matching-Overview) also offers some sophisticated file matching abilities
  * The [Software Heritage Project](https://archive.softwareheritage.org/) has massive ingestion capabilities and [offers an API](https://archive.softwareheritage.org/api/1/known/doc/) which can efficiently check whether a hash is known, and provide certain information on the file if so
  * [ClearlyDefined](https://docs.clearlydefined.io/using-data) provides licensing information for open source components, given their coordinates
  * [LGTM - Code Analysis Platform to Find and Prevent Vulnerabilities](https://lgtm.com/#explore) allows manually searching by GitHub repo
* For inputs acquired e.g., via `curl`:
  * [SpectralOps/preflight: preflight helps you verify scripts and executables to mitigate chain of supply attacks such as the recent Codecov hack.](https://github.com/spectralops/preflight)
  * [apiaryio/curl-trace-parser: Parser for output from Curl --trace option](https://github.com/apiaryio/curl-trace-parser)
    * [curl trace attestor · Issue #139 · testifysec/witness](https://github.com/testifysec/witness/issues/139)
  * [Friends don't let friends Curl | Bash](https://sysdig.com/blog/friends-dont-let-friends-curl-bash/)
  * [aquasecurity/tracee: Linux Runtime Security and Forensics using eBPF](https://github.com/aquasecurity/tracee)
* [dependency-check](https://jeremylong.github.io/DependencyCheck/index.html)
* [GitHub - DependencyTrack/dependency-track: Dependency-Track is an intelligent Component Analysis platform that allows organizations to identify and reduce risk in the software supply chain.](https://github.com/DependencyTrack/dependency-track)

### SCA and SBOM

> This section includes: package/library scanners and detectors, SBOM formats, standards, authoring and validation, and a few applications. Will likely include SCA.

* [What an SBOM Can Do for You](https://blog.chainguard.dev/what-an-sbom-can-do-for-you/)
* [awesomeSBOM/awesome-sbom: A curated list of SBOM (Software Bill Of Materials) related tools, frameworks, blogs, podcasts, and articles](https://github.com/awesomeSBOM/awesome-sbom)
* OWASP's [SCA tools](https://owasp.org/www-community/Source_Code_Analysis_Tools) list is comprehensive on its own
* [Grafeas: A Component Metadata API](https://github.com/grafeas/grafeas)
* [trailofbits/it-depends: A tool to automatically build a dependency graph and Software Bill of Materials (SBOM) for packages and arbitrary source code repositories.](https://github.com/trailofbits/it-depends)

### Vulnerability information exchange

* [OSV](https://osv.dev/)
* Qualys' [Vulnerability Detection Pipeline](https://community.qualys.com/vulnerability-detection-pipeline/)
* [Vuls · Agentless Vulnerability Scanner for Linux/FreeBSD](https://vuls.io/)
* [aquasecurity/trivy: Scanner for vulnerabilities in container images, file systems, and Git repositories, as well as for configuration issues](https://github.com/aquasecurity/trivy)
* [GitHub - cve-search/cve-search: cve-search - a tool to perform local searches for known vulnerabilities](https://github.com/cve-search/cve-search)
* [GitHub - nexB/vulnerablecode: A work-in-progress towards a free and open vulnerabilities database and the packages they impact. And the tools to aggregate and correlate these vulnerabilities. Sponsored by NLnet https://nlnet.nl/project/vulnerabilitydatabase/ for https://www.aboutcode.org/ Chat at https://gitter.im/aboutcode-org/vulnerablecode](https://github.com/nexB/vulnerablecode)

## Point-of-use validations

> This section includes: admission and ingestion policies, pull-time verification and end-user verifications.

* [ossf/allstar: GitHub App to set and enforce security policies](https://github.com/ossf/allstar)
* [Open Policy Agent](https://www.openpolicyagent.org/)
* [Conftest](https://www.conftest.dev/examples/) allows to write tests against structured configuration data using the Open Policy Agent Rego query language: [here's an example](https://github.com/open-policy-agent/conftest/blob/master/examples/docker/policy/commands.rego)

## Identity, signing and provenance

> This section includes: projects and discussions specifics to developer identity, OIDC, keyrings and related topics.

* [technosophos/helm-gpg: Chart signing and verification with GnuPG for Helm.](https://github.com/technosophos/helm-gpg)
* [notaryproject/notary: Notary is a project that allows anyone to have trust over arbitrary collections of data](https://github.com/notaryproject/notary)
* [latchset/tang: Tang binding daemon](https://github.com/latchset/tang)
* [An exposed apt signing key and how to improve apt security](https://blog.cloudflare.com/dont-use-apt-key/)

## Frameworks and best practice references

> This section includes: reference architectures and authoritative compilations of supply chain attacks and the emerging categories.

* [in-toto | A framework to secure the integrity of software supply chains](https://in-toto.io/)
* [Supply chain Levels for Software Artifacts](https://slsa.dev/) or SLSA (salsa) is a security framework, a check-list of standards and controls to prevent tampering, improve integrity, and secure packages and infrastructure in your projects, businesses or enterprises. 
* [OWASP Application Security Verification Standard](https://owasp.org/www-project-application-security-verification-standard/), esp. _V14 - Configuration_
* SAFECODE's [Fundamental Practices for Secure Software Development, Third Edition](https://safecode.org/uncategorized/fundamental-practices-secure-software-development/), esp. _Manage Security Risk Inherent in the Use of Third-party Components_
* [SSF | The Secure Software Factory](https://thesecuresoftwarefactory.github.io/ssf/) and [mlieberman85/supply-chain-examples](https://github.com/mlieberman85/supply-chain-examples)

## Build techniques

> This section includes: reproducible builds, hermetic builds, bootstrappable builds, special considerations for CI/CD systems, best practices building artifacts such as OCI containers, etc.

## Others in need of categorization

## Talks, articles, media coverage and other reading

* [“Chain”ging the Game - how runtime makes your supply chain even more secure](https://sysdig.com/blog/chainging-the-game/)
* [How to attack cloud infrastructure via a malicious pull request](https://goteleport.com/blog/hack-via-pull-request/)
* The [Technology](https://snyk.io/series/devsecops/technology/) chapter in Snyk's DevSecOps series
* [The Challenges of Securing the Open Source Supply Chain](https://thenewstack.io/the-challenges-of-securing-the-open-source-supply-chain/)
* [What is a Software Supply Chain Attestation - and why do I need it?](https://www.testifysec.com/blog/what-is-a-supply-chain-attestation/)
* [Open Policy Agent 2021, Year in Review](https://blog.openpolicyagent.org/open-policy-agent-2021-year-in-review-f334244868e0)

