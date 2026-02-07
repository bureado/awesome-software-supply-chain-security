# awesome-software-supply-chain-security

 [![Awesome](https://awesome.re/badge.svg)](https://awesome.re)

A compilation of resources in the software supply chain security domain, with emphasis on open source.

- [awesome-software-supply-chain-security](#awesome-software-supply-chain-security)
  - [About this list](#about-this-list)
  - [Dependency intelligence](#dependency-intelligence)
    - [SCA and SBOM](#sca-and-sbom)
    - [Vulnerability information exchange](#vulnerability-information-exchange)
  - [Point-of-use validations](#point-of-use-validations)
    - [Supply chain beyond libraries](#supply-chain-beyond-libraries)
  - [Identity, signing and provenance](#identity-signing-and-provenance)
  - [Frameworks and best practice references](#frameworks-and-best-practice-references)
  - [Build techniques](#build-techniques)
  - [Talks, articles, media coverage and other reading](#talks-articles-media-coverage-and-other-reading)
    - [Getting started and staying fresh](#getting-started-and-staying-fresh)

## About this list

There is no prescribed taxonomy for this domain. This list will necessarily have some overlap with disciplines and categories such as DevSecOps, SAST, SCA and more.

The [supply-chain-synthesis](https://github.com/AevaOnline/supply-chain-synthesis/) repo offers a long-form read on why that's the case, plus helpful pointers to understand and navigate it as it evolves.

For `awesome-software-supply-chain-security` we take the following high-level approach: different actors in the supply chain contribute **attestations** to the elements represented in the chain.

In this process-centric view, attestations are _emitted_, _augmented_ (e.g., during composition) and _verified_.

> Another way to look at this was described [here](https://twitter.com/joshbressers/status/1477366321436319745) by Josh Bressers, and here's a narrative example in the wild [from Spotify](https://youtu.be/yuDMsB0jsdE?t=498)

Using this lens we can identify a large group of "subjects" (dependencies), distinct categories of "facts" (licenses or vulnerabilities) and the specific role of identity, provenance and build systems. This is the rationale behind the current headings, which are expected to evolve with the domain.

> Other examples of the ongoing process to define the domain include [Add Bad Design as a supply chain scenario · Issue #249 · slsa-framework/slsa](https://github.com/slsa-framework/slsa/issues/249) and [How does SLSA fit into broader supply chain security? · Issue #276 · slsa-framework/slsa](https://github.com/slsa-framework/slsa/issues/276). [Check out this tweet from Aeva Black](https://twitter.com/aevavoom/status/1491479149227118597) with Dan Lorenc for another in-a-pinch view of a couple key projects.

## Dependency intelligence

> This section includes: package management, library management, dependency management, vendored dependency management, by-hash searches, package, library and dependency naming, library behavior labeling, library publishing, registries and repositories, publishing gates and scans, dependency lifecycle.

* [Open Source Insights](https://deps.dev/)
* [guacsec/guac: GUAC aggregates software security metadata into a high fidelity graph database.](https://github.com/guacsec/guac)
* [package-url/purl-spec: A minimal specification for purl aka. a package &quot;mostly universal&quot; URL, join the discussion at https://gitter.im/package-url/Lobby](https://github.com/package-url/purl-spec)
* Online services that help understand what a specific dependency _is_, or at least whether it's known (usually feeding it a package identifier, such as `purl`, CPE or another form of `ecosystem:name:version`, or alternatively via hash):
  * [NSRL](https://www.nist.gov/itl/ssd/software-quality-group/national-software-reference-library-nsrl/about-nsrl/library-contents): hashes for [COTS software](https://www.nist.gov/itl/ssd/software-quality-group/national-software-reference-library-nsrl/about-nsrl/library-contents), well-integrated in tooling from [sleuthkit/hfind](http://manpages.ubuntu.com/manpages/bionic/man1/hfind.1.html) to [nsrllookup](https://github.com/rjhansen/nsrllookup)
  * A source that can be queried via a public API (HTTP and DNS!) and can be more open source-aware is [CIRCL hashlookup](https://www.circl.lu/services/hashlookup/)
  * [Repology](https://repology.org/) has legendary coverage for Linux packages across multiple distribution; its [repology-updater](https://github.com/repology/repology-updater) and other infrastructure pieces are open source. It provides an updater for [WikiData](https://github.com/repology/repology-wikidata-bot) which also has properties of interest for the supply chain security domain.
  * Debian's [external repositories metadata](https://salsa.debian.org/extrepo-team/extrepo-data/-/tree/master/repos/debian)
  * Tidelift's [libraries.io](https://libraries.io/) provides an [API](https://libraries.io/api) and supports over 30 package ecosystems (and [several useful open source tools](https://github.com/librariesio))
  * WhiteSource's [Unified Agent](https://whitesource.atlassian.net/wiki/spaces/WD/pages/1140852201/Getting+Started+with+the+Unified+Agent#Binary-and-Source-File-Matching-Overview) also offers some sophisticated file matching abilities
  * The [Software Heritage Project](https://archive.softwareheritage.org/) has massive ingestion capabilities and [offers an API](https://archive.softwareheritage.org/api/1/known/doc/) which can efficiently check whether a hash is known, and provide certain information on the file if so
    * Also see [swh scanner CLI](https://docs.softwareheritage.org/devel/swh-scanner/cli.html)
  * [hashdd - Known Good Cryptographic Hashes](https://www.hashdd.com/#approach)
  * [ClearlyDefined](https://docs.clearlydefined.io/using-data) provides licensing information for open source components, given their coordinates
  * [LGTM - Code Analysis Platform to Find and Prevent Vulnerabilities](https://lgtm.com/#explore) allows manually searching by GitHub repo
  * [Binary Transparency directory](https://bintra.directory/) offers an API that allows to search packages by hash and other attributes
    * A somehow related read is the second half of [How Cloudflare verifies the code WhatsApp Web serves to users](https://blog.cloudflare.com/cloudflare-verifies-code-whatsapp-web-serves-users/#security-needs-to-be-convenient)
    * And [Subresource Integrity](https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity)
    * Not to be confused with the legendary read on [Binary Transparency](https://binary.transparency.dev/)
* For inputs acquired e.g., via `curl`:
  * [SpectralOps/preflight: preflight helps you verify scripts and executables to mitigate chain of supply attacks such as the recent Codecov hack.](https://github.com/spectralops/preflight)
  * [apiaryio/curl-trace-parser: Parser for output from Curl --trace option](https://github.com/apiaryio/curl-trace-parser)
    * [curl trace attestor · Issue #139 · testifysec/witness](https://github.com/testifysec/witness/issues/139)
  * [Friends don't let friends Curl | Bash](https://sysdig.com/blog/friends-dont-let-friends-curl-bash/)
    * And the quite interesting [Enable packaging of curl|bash and other wild stuff. by jordansissel · Pull Request #1957 · jordansissel/fpm](https://github.com/jordansissel/fpm/pull/1957#issuecomment-1304978342)
  * [Falco](https://falco.org/)
  * [aquasecurity/tracee: Linux Runtime Security and Forensics using eBPF](https://github.com/aquasecurity/tracee)
  * [genuinetools/bane: Custom &amp; better AppArmor profile generator for Docker containers.](https://github.com/genuinetools/bane)
  * [containers/oci-seccomp-bpf-hook: OCI hook to trace syscalls and generate a seccomp profile](https://github.com/containers/oci-seccomp-bpf-hook)
  * [bottlerocket-os/hotdog: Hotdog is a set of OCI hooks used to inject the Log4j Hot Patch into containers.](https://github.com/bottlerocket-os/hotdog)
* [deepfence/ThreatMapper: 🔥 🔥   Open source cloud native security observability platform. Linux, K8s, AWS Fargate and more. 🔥 🔥](https://github.com/deepfence/ThreatMapper)
* [dependency-check](https://jeremylong.github.io/DependencyCheck/index.html)
* [6mile/super-confused: Dependency confusion analysis tool supporting 17+ file formats and SBOM files](https://github.com/6mile/super-confused), identifying confusion opportunities across npm, PyPI, Cargo, Packagist, RubyGems, Maven, Go and other ecosystems
* [ossf/package-analysis: Open Source Package Analysis](https://github.com/ossf/package-analysis) and [ossf/package-feeds: Feed parsing for language package manager updates](https://github.com/ossf/package-feeds)
  * Related: [Introducing Package Analysis: Scanning open source packages for malicious behavior](https://openssf.org/blog/2022/04/28/introducing-package-analysis-scanning-open-source-packages-for-malicious-behavior/)
  * Also [Argo Security Automation with OSS-Fuzz](https://blog.argoproj.io/argo-security-automation-with-oss-fuzz-da38c1f86452), [Improving Security by Fuzzing the CNCF landscape](https://www.cncf.io/blog/2022/06/28/improving-security-by-fuzzing-the-cncf-landscape/) and [google/oss-fuzz: OSS-Fuzz - continuous fuzzing for open source software.](https://github.com/google/oss-fuzz)
  * And [ClusterFuzzLite](https://google.github.io/clusterfuzzlite/)
  * For Node.js: [CodeIntelligenceTesting/jazzer.js: Coverage-guided, in-process fuzzing for the Node.js](https://github.com/CodeIntelligenceTesting/jazzer.js)
  * Also, although arguably more in the realm of application observability, [IntelLabs/control-flag: A system to flag anomalous source code expressions by learning typical expressions from training data](https://github.com/IntelLabs/control-flag)
* [abhisek/supply-chain-security-gateway: Reference architecture and proof of concept implementation for supply chain security gateway](https://github.com/abhisek/supply-chain-security-gateway)
* [cugu/gocap: List your dependencies capabilities and monitor if updates require more  capabilities.](https://github.com/cugu/gocap)
* [MATE: Interactive Program Analysis with Code Property Graphs](https://galois.com/blog/2022/08/mate-interactive-program-analysis-with-code-property-graphs/) and see [GaloisInc/MATE: MATE is a suite of tools for interactive program analysis with a focus on hunting for bugs in C and C++ code using Code Property Graphs](https://github.com/GaloisInc/MATE) and [docs](https://galoisinc.github.io/MATE/)
* [Checkmarx/chainalert-github-action: scans popular packages and alerts in cases there is suspicion of an account takeover](https://github.com/Checkmarx/chainalert-github-action)
* Open Source Security Foundation (OpenSSF) [Alpha-Omega Project](https://openssf.org/community/alpha-omega/)
* [Socket - Find and compare millions of open source packages](https://socket.dev/), focused on JavaScript
* [diffoscope: in-depth comparison of files, archives, and directories](https://diffoscope.org/)
* [RedHatProductSecurity/component-registry: Component Registry (Corgi) aggregates component data across Red Hat's supported products, managed services, and internal product pipeline services.](https://github.com/RedHatProductSecurity/component-registry)
* [OSS Insight](https://ossinsight.io/), powered by TIDB Cloud, is an insight tool that can help you analyze in depth any single GitHub repository/developers, compare any two repositories using the same metrics, and provide comprehensive, valuable, and trending open source insights.
* [Announcing the Private Beta of FOSSA Risk Intelligence](https://fossa.com/blog/announcing-private-beta-risk-intelligence/)
* From [Projects | Software Transparency Foundation](https://st.foundation/projects), see [OSSKB | Free Open Source Inventorying](https://osskb.org/)
  * And particularly: [scanoss.py/PACKAGE.md at main · scanoss/scanoss.py](https://github.com/scanoss/scanoss.py/blob/main/PACKAGE.md)
* [Artifact Hub](https://artifacthub.io/), featuring [Packages security report](https://artifacthub.io/docs/topics/security_report/) and also [verifies with cosign](https://artifacthub.io/docs/topics/repositories/#kubewarden-policies-repositories)
* [crt.sh | Certificate Search](https://crt.sh/)
* [grep.app | code search](https://grep.app/)
* [GitHub code search](https://github.com/features/code-search)
* [searchcode | source code search engine](https://searchcode.com/)
* [Sourcegraph](https://sourcegraph.com/search) from Sourcegraph
* [Onboard open-source contributors on Open Source Hub](https://opensourcehub.io/), see the [docker-slim](https://opensourcehub.io/docker-slim/docker-slim) example in Codesee
* [Code Checker](https://snyk.io/code-checker/) from Snyk
* [Get Started - FOSSology](https://www.fossology.org/get-started/)
* [cve-search/git-vuln-finder: Finding potential software vulnerabilities from git commit messages](https://github.com/cve-search/git-vuln-finder)
* [chaoss/augur: Python library and web service for Open Source Software Health and Sustainability metrics &amp; data collection. You can find our documentation and new contributor information easily here: https://chaoss.github.io/augur/ and learn more about Augur at our website https://augurlabs.io](https://github.com/chaoss/augur)
* [IBM/CBOM: Cryptography Bill of Materials](https://github.com/IBM/CBOM)
* [AppThreat/blint: BLint is a Binary Linter to check the security properties, and capabilities in your executables. It is powered by lief.](https://github.com/AppThreat/blint)

Also read:

* [TaptuIT/awesome-devsecops: Curating the best DevSecOps resources and tooling.](https://github.com/TaptuIT/awesome-devsecops#dependency-management)
* Read: [Contour: A Practical System for Binary Transparency](https://arxiv.org/abs/1712.08427)
* Several interesting concepts in: [Shopify/seer-prototype: Security Expert Elicitation of Risks](https://github.com/Shopify/seer-prototype/tree/main)

### SCA and SBOM

> This section includes: package/library scanners and detectors, SBOM formats, standards, authoring and validation, and a few applications. Will likely include SCA.

The most complete reference is [awesomeSBOM/awesome-sbom](https://github.com/awesomeSBOM/awesome-sbom). Another helpful repo focusing on generators is [cybeats/sbomgen: List of SBOM Generation Tools](https://github.com/cybeats/sbomgen).

* [GitBOM](https://gitbom.dev/)
  * Also: [git-bom/bomsh: bomsh is collection of tools to explore the GitBOM idea](https://github.com/git-bom/bomsh#Reproducible-Build-and-Bomsh)
  * [yonhan3/gitbom-repo: A repository of gitBOM docs for Linux binaries](https://github.com/yonhan3/gitbom-repo)
  * Listen: [GitBOM. It’s not Git or SBOM](https://thectoadvisor.com/gitbom-podcast/) and [GitBOM: Repurposing Git’s Graph for Supply Chain Security & Transparency](https://www.youtube.com/watch?v=qcQFIv6pCSE)
  * Also see [bomsage/vision.md at main · dpp/bomsage](https://github.com/dpp/bomsage/blob/main/info/vision.md), and [pkgconf/main.c at master · pkgconf/pkgconf](https://github.com/pkgconf/pkgconf/blob/master/cli/bomtool/main.c) (more info in [this thread](https://twitter.com/ariadneconill/status/1558074556723728387))
* [nexB/scancode-toolkit: ScanCode detects licenses, copyrights, package manifests &amp; dependencies and more by scanning code ... to discover and inventory open source and third-party packages used in your code.](https://github.com/nexB/scancode-toolkit)
* OWASP's [SCA tools](https://owasp.org/www-community/Source_Code_Analysis_Tools) list is comprehensive on its own
* [Grafeas: A Component Metadata API](https://github.com/grafeas/grafeas)
* [trailofbits/it-depends: A tool to automatically build a dependency graph and Software Bill of Materials (SBOM) for packages and arbitrary source code repositories.](https://github.com/trailofbits/it-depends)
* [Mend SCA SBOM](https://www.mend.io/sbom/), [Mend Bolt: Find and Fix Open Source vulnerabilities](https://www.mend.io/free-developer-tools/bolt/) and [Whitesource Renovate: Automated Dependency Updates](https://www.whitesourcesoftware.com/free-developer-tools/renovate/)
  * [renovatebot/renovate: Universal dependency update tool that fits into your workflows.](https://github.com/renovatebot/renovate)
    * Also read [Use Cases - Renovate Docs](https://docs.renovatebot.com/getting-started/use-cases/)
* [JFrog Xray - Universal Component Analysis &amp; Container Security Scanning](https://jfrog.com/xray/)
* [DependencyTrack/dependency-track: Dependency-Track is an intelligent Component Analysis platform that allows organizations to identify and reduce risk in the software supply chain.](https://github.com/DependencyTrack/dependency-track)
  * [Good read on Dependency-Track](https://tomalrichblog.blogspot.com/2022/06/the-first-complete-sbom-tool.html?m=1)
* [guacsec/trustify](https://github.com/guacsec/trustify) provides a searchable abstraction over CycloneDX/SPDX SBOMs, cross-referencing against security advisories to identify vulnerabilities. See [docs](https://docs.trustification.dev/trustify/index.html)
* [trustification/trustification: A collection of services for storing and managing SBOMs and VEX documents](https://github.com/trustification/trustification) (Bombastic, Vexination, V11y, Collectorist, Spog) with vulnerability lookup, impact analysis, search, and sharing capabilities via Helm chart or single binary
* [eclipse-sw360/sw360](https://github.com/eclipse-sw360/sw360) is an open source software component catalogue for managing software components, licenses, and compliance with SPDX support. See [eclipse.dev/sw360/](https://eclipse.dev/sw360/)
* [oss-review-toolkit/ort: A suite of tools to assist with reviewing Open Source Software dependencies.](https://github.com/oss-review-toolkit/ort)
* [anchore/syft: CLI tool and library for generating a Software Bill of Materials from container images and filesystems](https://github.com/anchore/syft) from [Software supply chain security solutions • Anchore](https://anchore.com/)
  * Also note: [New `docker sbom` Command Creates SBOMs Using Syft](https://anchore.com/sbom/docker-sbom-command-creates-sbom-using-syft/)
  * [Creating SBOM Attestations Using Syft and Sigstore](https://anchore.com/sbom/creating-sbom-attestations-using-syft-and-sigstore/)
  * Simple flow: [utils/ci/github/docker-build-sign-sbom at main · marco-lancini/utils](https://github.com/marco-lancini/utils/tree/main/ci/github/docker-build-sign-sbom)
* [ANNOUNCE: Scan is now in maintenance mode · Issue #352 · ShiftLeftSecurity/sast-scan](https://github.com/ShiftLeftSecurity/sast-scan/issues/352)
* [Container Security | Qualys, Inc.](https://www.qualys.com/apps/container-security/)
* [Aqua Cloud Native Security, Container Security &amp; Serverless Security](https://www.aquasec.com/)
* [tern-tools/tern: Tern is a software composition analysis tool and Python library that generates a Software Bill of Materials for container images and Dockerfiles. The SBOM that Tern generates will give you a layer-by-layer view of what's inside your container in a variety of formats including human-readable, JSON, HTML, SPDX and more.](https://github.com/tern-tools/tern)
* [REA-Products/C-SCRM-Use-Case at master · rjb4standards/REA-Products](https://github.com/rjb4standards/REA-Products/tree/master/C-SCRM-Use-Case) from [this tweet](https://twitter.com/rjb4standards/status/1481250447331573761?s=12)
  * Also see [Energy SBOM Proof of Concept - INL](https://inl.gov/sbom-poc/)
* [Phylum Analyze PR Action: GitHub Action to analyze Pull Requests for open-source supply chain issues](https://github.com/phylum-dev/phylum-analyze-pr-action) from [Phylum | The Software Supply Chain Security Company](https://phylum.io/)
* [microsoft/component-detection: Scans your project to determine what components you use](https://github.com/microsoft/component-detection/)
* [DWARF 5 Standard](https://dwarfstd.org/Dwarf5Std.php)
* [Software Identification (SWID) Tagging | CSRC](https://csrc.nist.gov/projects/software-identification-swid/guidelines) and [Guidelines for the Creation of Interoperable Software Identification (SWID) Tags](https://nvlpubs.nist.gov/nistpubs/ir/2016/NIST.IR.8060.pdf)
* [Concise Software Identification Tags](https://www.ietf.org/archive/id/draft-ietf-sacm-coswid-18.html)
* [hughsie/python-uswid: A tiny tool for embedding CoSWID tags in EFI binaries](https://github.com/hughsie/python-uswid)
  * Also see [thread](https://twitter.com/hughsient/status/1498259857341915139?s=120)
    * And practical example [in coreboot](https://review.coreboot.org/c/coreboot/+/63639)
* [ckotzbauer/sbom-operator: Catalogue all images of a Kubernetes cluster to multiple targets with Syft](https://github.com/ckotzbauer/sbom-operator)
* [Security problem management](https://www.dynatrace.com/support/help/how-to-use-dynatrace/application-security/security-problem-management) in Dynatrace Application Security
* [DefectDojo/django-DefectDojo: DefectDojo is a DevSecOps and vulnerability management tool.](https://github.com/DefectDojo/django-DefectDojo)
  * Impressive list of integrations with samples: [DefectDojo/sample-scan-files: Sample scan files for testing DefectDojo imports](https://github.com/DefectDojo/sample-scan-files)
* [swingletree-oss/swingletree: Integrate and observe the results of your CI/CD pipeline tools](https://github.com/swingletree-oss/swingletree)
* [mercedes-benz/sechub: SecHub - one central and easy way to use different security tools with one API/Client](https://github.com/mercedes-benz/sechub)
* [marcinguy/betterscan-ce: Code Scanning/SAST/Static Analysis/Linting using many tools/Scanners with One Report (Code, IaC) - Betterscan Community Edition (CE)](https://github.com/marcinguy/betterscan-ce)
* [BBVA/susto: Systematic Universal Security Testing Orchestration](https://github.com/BBVA/susto)
* [AppThreat/rosa: An experiment that looks very promising so far.](https://github.com/AppThreat/rosa)
* FOSSA's [SBOM Solution](https://fossa.com/lp/simplify-sbom-generation-fossa)
* [Rezillion Dynamic SBOM](https://www.rezilion.com/platform/dynamic-sbom/)
* [opensbom-generator/spdx-sbom-generator: Support CI generation of SBOMs via golang tooling.](https://github.com/opensbom-generator/spdx-sbom-generator)
* Tauruseer's [SBOM tools](https://www.tauruseer.com/platform/dynamic-software-bill-of-materials-SBOM)
* SOOS' [Supported Languages & Manifests](https://kb.soos.io/help/soos-languages-supported)
* Fortress: [Software Bill of Materials](https://www.fortressinfosec.com/sbom)
* [javixeneize/yasca: Yet Another SCA tool](https://github.com/javixeneize/yasca)
* Cybeats [SBOM Studio](https://www.cybeats.com/sbom-studio)
* [DeepBOM](https://www.deepbits.com/platform) from Deepbits, an AI-powered platform for SBOM management, vulnerability assessment, malware detection and license compliance
* [edgebitio/edgebit-build: GitHub action to upload SBOMs to EdgeBit and receive vulnerability context in your pull requests](https://github.com/edgebitio/edgebit-build) from [EdgeBit - Real-time supply chain security, enabling security teams to target and coordinate vulnerability remediation without toil.](https://edgebit.io/)
* REA's [Software Assurance Guardian Point Man (SAG-PM)](https://reliableenergyanalytics.com/products)
* [microsoft/sbom-tool: The SBOM tool is a highly scalable and enterprise ready tool to create SPDX 2.2 compatible SBOMs for any variety of artifacts](https://github.com/microsoft/sbom-tool)
* Veracode's [SCA to Automate Security Scanning](https://www.veracode.com/products/software-composition-analysis), see demo: [How to generate a Software Bill of Materials (SBOM) using Veracode Software Composition Analysis](https://www.youtube.com/watch?v=FfTgeHjEwkk)
* [Enterprise Edition - BluBracket: Code Security & Secret Detection](https://blubracket.com/products/enterprise-edition/)
* [Software Composition Analysis (SCA) | CyberRes](https://www.microfocus.com/en-us/cyberres/application-security/software-composition-analysis)
* [Nexus Intelligence - Sonatype Data Services](https://www.sonatype.com/products/intelligence)
* [AppThreat/dep-scan: Fully open-source security audit for project dependencies based on known vulnerabilities and advisories. Supports both local repos and container images. Integrates with various CI environments such as Azure Pipelines, CircleCI, Google CloudBuild. No server required!](https://github.com/AppThreat/dep-scan)
* [sbs2001/fatbom: fatbom (Fat Bill Of Materials) is a tool which combines the SBOM generated by various tools into one fat SBOM. Thus leveraging each tool&#39;s strength.](https://github.com/sbs2001/fatbom)
* [Sonatype BOM Doctor](https://bomdoctor.sonatype.dev/#/home)
* [jhutchings1/spdx-to-dependency-graph-action: A GitHub Action that takes SPDX SBOMs and uploads them to GitHub&#39;s dependency submission API to power Dependabot alerts](https://github.com/jhutchings1/spdx-to-dependency-graph-action)
  * Also see: [evryfs/sbom-dependency-submission-action: Submit SBOMs to GitHub&#39;s dependency submission API](https://github.com/evryfs/sbom-dependency-submission-action)
  * And the [Dependency submission](https://docs.github.com/en/rest/dependency-graph/dependency-submission) docs
* [tap8stry/orion: Go beyond package manager discovery for SBOM](https://github.com/tap8stry/orion)
* [patriksvensson/covenant: A tool to generate SBOM (Software Bill of Material) from source code artifacts.](https://github.com/patriksvensson/covenant)
* [CycloneDX/cyclonedx-webpack-plugin: Create CycloneDX Software Bill of Materials (SBOM) from webpack bundles at compile time.](https://github.com/CycloneDX/cyclonedx-webpack-plugin)
* [advanced-security/gh-sbom: Generate SBOMs with gh CLI](https://github.com/advanced-security/gh-sbom)
* [SoftwareDesignLab/SBOM-in-a-Box](https://github.com/SoftwareDesignLab/SBOM-in-a-Box), a unified platform for SBOM generation (using integrated open source tools), conversion (SPDX/CycloneDX), VEX generation, quality metrics, comparison and merging
* [philips-software/SPDXMerge: Tool for merging multiple SPDX JSON/Tag-value SBOMs into a parent SBOM](https://github.com/philips-software/SPDXMerge), supporting deep merge (consolidate contents) and shallow merge (create references) with GitHub Action and Docker support
* [interlynk-io/sbomqs: SBOM quality score - Quality metrics for your sboms](https://github.com/interlynk-io/sbomqs)
* [eBay/sbom-scorecard: Generate a score for your sbom to understand if it will actually be useful.](https://github.com/eBay/sbom-scorecard)
* Read: [An Empirical Study of the SBOM Landscape](https://arxiv.org/abs/2303.11102), a deep-dive into 6 SBOM tools and the accuracy of the SBOMs they produce for complex open-source Java projects (IEEE Security & Privacy, 2023)
  * Also see: [How to Quickly Measure SBOM Accuracy for Free](https://www.endorlabs.com/learn/how-to-quickly-measure-sbom-accuracy-for-free) from Endor Labs, with a reproducible script at [endorlabs/sbom-lab](https://github.com/endorlabs/sbom-lab)
* Read: [OWASP CycloneDX — Authoritative Guide to SBOM](https://cyclonedx.org/guides/OWASP_CycloneDX-Authoritative-Guide-to-SBOM-en.pdf), a comprehensive PDF guide on Software Bill of Materials, formats, and best practices
* [SBOM Insights](https://sbom-insights.dev/) blog covering SBOM compliance frameworks (NTIA minimum elements, BSI standards), quality scoring with sbomqs, and practical SBOM use cases
* [cyfinoid/aibommaker: AI BOM Generator](https://github.com/cyfinoid/aibommaker), a client-side web tool for analyzing GitHub repositories for AI/LLM usage and generating AI Bills of Materials in CycloneDX 1.7 and SPDX 3.0.1 formats with hardware, infrastructure, and governance detection

More interesting resources:

* [Brakeing Down Security Podcast: 2020-031-Allan Friedman, SBOM, software transparency, and knowing how the sausage is made](https://brakeingsecurity.com/2020-031-allan-friedman-sbom-software-transparency-and-knowing-how-the-sausage-is-made?tdest_id=282477)
* [Episode 312: The Legend of the SBOM](https://opensourcesecurity.io/2022/02/27/episode-312-the-legend-of-the-sbom/)
* [Reimagining Cyber Podcast: Log4j vulnerability provides harsh lessons in unknown dependencies](https://community.microfocus.com/cyberres/b/sws-22/posts/reimagining-cyber-podcast-log4j-vulnerability-provides-harsh-lessons-in-unknown-dependencies)
* [Tech Debt Burndown Podcast Series 1 E11: Allan Friedman and SBOMs](https://techdebtburndown.com/episode11/)
* [Sounil Yu on SBOMs, software supply chain security - Security Conversations](https://securityconversations.com/episode/sounil-yu-on-sboms-software-supply-chain-security/)
* [Exploring Security. Criticality of SBOM. Scott McGregor, Cloud Security, Wind River](https://soundcloud.com/cybercrimemagazine/exploring-security-criticality-of-sbom-scott-mcgregor-cloud-security-wind-river)
* [Down the Security Rabbithole Podcast: DtSR Episode 487 - Software Supply Chain is a BFD](http://podcast.wh1t3rabbit.net/dtsr-episode-487-software-supply-chain-is-a-bfd?tdest_id=609232)
* [Software Composition Analysis Podcast: Software Supply Chain - Episode 1](https://www.youtube.com/watch?v=ryRV-bAyHXY&list=PLnaFG2n4CcbNi9wtjKZLh2m4cANoqNcgu)
* [Critical Update: Do You Know What’s In Your Software?](https://www.nextgov.com/podcasts/2021/05/critical-update-do-you-know-whats-your-software/174100/)
* [Software Bill of Materials | CISA](https://www.cisa.gov/sbom)
* [SBOM Use Case - RKVST](https://www.rkvst.com/share-sboms/) and [RKVST SBOM Hub - RKVST](https://www.rkvst.com/rkvst-sbom-hub/)
  * Also read: [SBOM Hub - NTIA Attribute Mappings](https://support.rkvst.com/hc/en-gb/articles/6023134387601-SBOM-Hub-NTIA-Attribute-Mappings)
* [BOF: SBOMs for Embedded Systems: What's Working, What's Not? - Kate Stewart, Linux Foundation](https://www.youtube.com/watch?v=E17RvPlVbQI)
* [All About That BoM, ‘bout That BoM - Melba Lopez, IBM](https://www.youtube.com/watch?v=lm7ySgCeALk)
* [OWASP CycloneDX Launches SBOM Exchange API](https://cyclonedx.org/news/owasp-cyclonedx-launches-sbom-exchange-api-standardizing-sbom-distribution/)
* Read: [SBOM Management | Six Ways It Prevents SBOM Sprawl](https://anchore.com/sbom/sbom-management-and-six-ways-it-prevents-sbom-sprawl/)
* Read: NTIA's [The Minimum Elements For a Software Bill of Materials](https://www.ntia.doc.gov/files/ntia/publications/sbom_minimum_elements_report.pdf)
* Read: [What an SBOM Can Do for You](https://blog.chainguard.dev/what-an-sbom-can-do-for-you/)

A few open source projects are documenting, in public, how they acquire dependencies. This intentional, human-parsable, long-form examples can be illustrative:

* [envoy/DEPENDENCY_POLICY.md at main · envoyproxy/envoy](https://github.com/envoyproxy/envoy/blob/main/DEPENDENCY_POLICY.md)
* [What curl expects from dependencies](https://daniel.haxx.se/blog/2022/03/28/what-curl-expects-from-dependencies/)
* [Security: The Value of SBOMs](https://fluxcd.io/blog/2022/02/security-the-value-of-sboms/) from Flux

### Vulnerability information exchange

* [OSV](https://osv.dev/)
  * Read: [SBOM in Action: finding vulnerabilities with a Software Bill of Materials](https://security.googleblog.com/2022/06/sbom-in-action-finding-vulnerabilities.html?m=1)
  * Related: [spdx/spdx-to-osv: Produce an Open Source Vulnerability JSON file based on information in an SPDX document](https://github.com/spdx/spdx-to-osv/)
  * Tools: [google/osv-scanner: Vulnerability scanner written in Go which uses the data provided by https://osv.dev](https://github.com/google/osv-scanner)
* Qualys' [Vulnerability Detection Pipeline](https://community.qualys.com/vulnerability-detection-pipeline/)
* [Vuls · Agentless Vulnerability Scanner for Linux/FreeBSD](https://vuls.io/)
* [Vulnerability Database](https://vuldb.com/?), an [API](https://vuldb.com/?kb.api) is also available; see [VulDB](https://github.com/vuldb)
* [AppThreat/vulnerability-db: Vulnerability database and package search for sources such as OSV, NVD, GitHub and npm.](https://github.com/AppThreat/vulnerability-db)
* [vulnerability-lookup/vulnerability-lookup: Vulnerability correlation platform with multi-source feeds](https://github.com/vulnerability-lookup/vulnerability-lookup) (NVD, GitHub, OSV, national databases), CVD management, sightings tracking, comments, bundles, and API for rapid lookup and cross-source correlation
* [aquasecurity/trivy: Scanner for vulnerabilities in container images, file systems, and Git repositories, as well as for configuration issues](https://github.com/aquasecurity/trivy)
* [SAST for Code Security | Snyk Code](https://snyk.io/product/snyk-code/)
  * Also see: [Choosing Open Source Libraries](https://www.youtube.com/watch?app=desktop&v=Q4Yv3VGPiy4) from Snyk
* [Contrast Community Edition](https://www.contrastsecurity.com/contrast-community-edition)
* [Known Exploited Vulnerabilities Catalog | CISA](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
* [TURROKS/CVE_Prioritizer: Prioritize vulnerability patching by combining CVSS, EPSS, CISA KEV, and VulnCheck data](https://github.com/TURROKS/CVE_Prioritizer)
* [cve-search/cve-search: cve-search - a tool to perform local searches for known vulnerabilities](https://github.com/cve-search/cve-search)
* [Exein-io/kepler: NIST-based CVE lookup store and API powered by Rust](https://github.com/Exein-io/kepler)
* [nexB/vulnerablecode: A work-in-progress towards a free and open vulnerabilities database and the packages they impact. And the tools to aggregate and correlate these vulnerabilities. Sponsored by NLnet https://nlnet.nl/project/vulnerabilitydatabase/ for https://www.aboutcode.org/ Chat at https://gitter.im/aboutcode-org/vulnerablecode](https://github.com/nexB/vulnerablecode)
* [toolswatch/vFeed: The Correlated CVE Vulnerability And Threat Intelligence Database API](https://github.com/toolswatch/vFeed)
* [ossf/scorecard: Security Scorecards - Security health metrics for Open Source](https://github.com/ossf/scorecard), [OpenSSF Metrics](https://metrics.openssf.org/) and [ossf/security-reviews: A community collection of security reviews of open source software components.](https://github.com/ossf/security-reviews)
  * [ossf/scorecard-action: Official GitHub Action for OSSF Scorecards.](https://github.com/ossf/scorecard-action)
    * Note: [How OpenSSF Scorecard’s GitHub Action v2 action uses GitHub OIDC with Sigstore](https://github.com/sigstore/community/issues/125#issuecomment-1240965050)
  * Also [OpenSSF Security Insights Spec](https://github.com/ossf/security-insights-spec)
  * Read: [How OpenSSF Scorecards can help to evaluate open-source software risks](https://www-csoonline-com.cdn.ampproject.org/c/s/www.csoonline.com/article/3668192/how-openssf-scorecards-can-help-to-evaluate-open-source-software-risks.amp.html)
  * Great real life example: [State of the Eclipse Foundation GitHub repositories](https://mikael.barbero.tech/blog/post/eclipsefdn-scorecard-aug2022/)
  * Also see: [naveensrinivasan/scorecard-1000-critical-projects](https://github.com/naveensrinivasan/scorecard-1000-critical-projects), using the Scorecard API to analyze the top 1000 critical open source projects from the [Criticality Score](https://github.com/ossf/criticality_score) dataset
* [Lynis - Security auditing and hardening tool for Linux/Unix](https://cisofy.com/lynis/)
* [victims/victims-cve-db: CVE database store](https://github.com/victims/victims-cve-db)
* [anchore/grype: A vulnerability scanner for container images and filesystems](https://github.com/anchore/grype)
  * Also see [Using Grype to Identify GitHub Action Vulnerabilities](https://anchore.com/blog/using-grype-to-identify-github-action-vulnerabilities/)
  * And also [Grype now supports CycloneDX and SPDX standards](https://anchore.com/sbom/grype-support-cyclonedx-spdx/)
* [GitHub Advisory Database now open to community contributions](https://github.blog/2022-02-22-github-advisory-database-now-open-to-community-contributions/)
* [Global Security Database Working Group | CSA](https://cloudsecurityalliance.org/research/working-groups/global-security-database/), also see [cloudsecurityalliance/gsd-database: Global Security Database](https://github.com/cloudsecurityalliance/gsd-database)
* [trickest/cve: Gather and update all available and newest CVEs with their PoC.](https://github.com/trickest/cve)
* [RFC 9116: A File Format to Aid in Security Vulnerability Disclosure](https://www.rfc-editor.org/rfc/rfc9116)
* An AOSP vuln-to-commit exercise: [quarkslab/aosp_dataset: Large Commit Precise Vulnerability Dataset based on AOSP CVE](https://github.com/quarkslab/aosp_dataset)
  * [Commit Level Vulnerability Dataset](https://blog.quarkslab.com/commit-level-vulnerability-dataset.html)
* [nyph-infosec/daggerboard](https://github.com/nyph-infosec/daggerboard)
* [davideshay/vulnscan: Vulnerability Scanner Suite based on grype and syft from anchore](https://github.com/davideshay/vulnscan#readme)
* [devops-kung-fu/bomber: Scans SBoMs for security vulnerabilities](https://github.com/devops-kung-fu/bomber)
* Fortress: [Vulnerability Management](https://www.fortressinfosec.com/product-security/vulnerability-management)
* [Vulnerability Management | aDolus](https://adolus.com/solutions/vulnerability-management/)
* [secvisogram/secvisogram: Secvisogram is a web tool for creating and editing security advisories in the CSAF 2.0 format](https://github.com/secvisogram/secvisogram/)
* [future-architect/vuls: Agent-less vulnerability scanner for Linux, FreeBSD, Container, WordPress, Programming language libraries, Network devices](https://github.com/future-architect/vuls)
* [infobyte/faraday: Open Source Vulnerability Management Platform](https://github.com/infobyte/faraday) from [Faraday - Community v4 Release](https://faradaysec.com/community-v4/)
* [mitre/saf: The MITRE Security Automation Framework (SAF) Command Line Interface (CLI) brings together applications, techniques, libraries, and tools developed by MITRE and the security community to streamline security automation for systems and DevOps pipelines](https://github.com/mitre/saf)
* [devops-kung-fu/bomber: Scans Software Bill of Materials (SBOMs) for security vulnerabilities](https://github.com/devops-kung-fu/bomber)
* [Rezilion/mi-x: Determine whether your compute is truly vulnerable to a specific vulnerability by accounting for all factors which affect *actual* exploitability (runtime execution, configuration, permissions, existence of a mitigation, OS, etc..)](https://github.com/Rezilion/mi-x)
* [ossf-cve-benchmark/ossf-cve-benchmark: The OpenSSF CVE Benchmark consists of code and metadata for over 200 real life CVEs, as well as tooling to analyze the vulnerable codebases using a variety of static analysis security testing (SAST) tools and generate reports to evaluate those tools.](https://github.com/ossf-cve-benchmark/ossf-cve-benchmark)
* See the [Vulnerability Management](https://open-docs.neuvector.com/scanning/scanning/vulnerabilities) in the NeuVector Docs for integration examples in container scenarios
* [noqcks/xeol: An end-of-life (EOL) package scanner for container images, systems, and SBOMs](https://github.com/noqcks/xeol)
* [mchmarny/vimp: Compare data from multiple vulnerability scanners to get a more complete picture of potential exposures.](https://github.com/mchmarny/vimp)

A dedicated section on VEX reads:

* [CycloneDX - Vulnerability Exploitability Exchange (VEX)](https://cyclonedx.org/capabilities/vex/)
  * [Vulnerability eXploitability Exchange explained: How VEX makes SBOMs actionable](https://www.csoonline.com/article/3669810/vulnerability-exploitability-exchange-explained-how-vex-makes-sboms-actionable.html)
  * [How VEX helps SBOM+SLSA improve supply chain visibility | Google Cloud Blog](https://cloud.google.com/blog/products/identity-security/how-vex-helps-sbomslsa-improve-supply-chain-visibility)
  * [What is VEX and What Does it Have to Do with SBOMs?](https://blog.adolus.com/what-is-vex-and-what-does-it-have-to-do-with-sboms)
  * [What is VEX? It's the Vulnerability Exploitability eXchange!](https://zt.dev/posts/what-is-vex/)
  * [The Vulnerability Exploitability eXchange (VEX) standard](https://www.linkedin.com/pulse/vulnerability-exploitability-exchange-vex-standard-walter-haydock)
  * [Vex and SBOMs](https://docs.google.com/presentation/d/1lfhwgSnBXUViSAUNKVPVMUi0sGROwTNWImk5dzPiF38/edit?usp=sharing)
  * [VDR or VEX – Which Do I Use? Part 1](https://www.linkedin.com/pulse/vdr-vex-which-do-i-use-tony-turner)
  * [VEX! or... How to Reduce CVE Noise With One Simple Trick!](https://www.youtube.com/watch?v=OWAn3ynhyzQ) by Frederick Kautz
  * [Vulnerability Exploitability eXchange (VEX) - Status Justifications](https://www.cisa.gov/sites/default/files/publications/VEX_Status_Justification_Jun22.pdf)
* [Real-time VEX](https://tomalrichblog.blogspot.com/2022/09/real-time-vex.html?m=1)

Also see:

* [Vulncode-DB](https://www.vulncode-db.com/end) on deprecation path
* [GitHub brings supply chain security features to the Rust community](https://github.blog/2022-06-06-github-brings-supply-chain-security-features-to-the-rust-community/)
* [CyCognito Adopts Mapping ATT&CK to CVE for Impact](https://info.mitre-engenuity.org/hubfs/Center%20for%20Threat%20Informed%20Defense/Adoption%20Spotlight_CVE%20for%20Impact_CTID_CyCognito_20220622_Final.pdf)
* Read: [A closer look at CVSS scores](https://theoryof.predictable.software/articles/a-closer-look-at-cvss-scores/), [Patch Madness: Vendor Bug Advisories Are Broken, So Broken](https://www.darkreading.com/risk/patch-madness-vendor-bug-advisories-broken) and [An Incomplete Look at Vulnerability Databases & Scoring Methodologies](https://medium.com/@chris.hughes_11070/an-incomplete-look-at-vulnerability-databases-scoring-methodologies-7be7155661e8)
* Read: [How to Analyze an SBOM](https://cloudsmith.com/blog/how-to-analyze-an-sbom/) and [How to Generate and Host SBoMs](https://cloudsmith.com/blog/how-to-generate-and-host-an-sbom/) from Cloudsmith
* Read: [After the Advisory](https://blog.deps.dev/after-the-advisory/) from Google's Open Source Insights team

## Point-of-use validations

> This section includes: admission and ingestion policies, pull-time verification and end-user verifications.

* [Kyverno](https://kyverno.io/)
  * Read: [Attesting Image Scans With Kyverno](https://neonmirrors.net/post/2022-07/attesting-image-scans-kyverno/)
    * And: [Managing Kyverno Policies as OCI Artifacts with OCIRepository Sources](https://fluxcd.io/blog/2022/08/manage-kyverno-policies-as-ocirepositories/)
  * Also: [testifysec/judge-k8s: Proof of concept Kubernetes admission controller using the witness attestation verification library](https://github.com/testifysec/judge-k8s)
* [ckotzbauer/sbom-operator: Catalogue all images of a Kubernetes cluster to multiple targets with Syft](https://github.com/ckotzbauer/sbom-operator)
* [CONNAISSEUR - Verify Container Image Signatures in Kubernetes](https://sse-secure-systems.github.io/connaisseur/v2.0.0/)
* [sigstore/policy-controller: The policy admission controller used to enforce policy on a cluster on verifiable supply-chain metadata from cosign.](https://github.com/sigstore/policy-controller)
  * Also see: [lukehinds/policy-controller-demo: demo of keyless signing with the sigstore kubernetes policy controller](https://github.com/lukehinds/policy-controller-demo)
* [portieris/POLICIES.md at main · IBM/portieris](https://github.com/IBM/portieris/blob/main/POLICIES.md)
* [reproducible-containers/repro-get: Reproducible apt/dnf/apk/pacman, with content-addressing](https://github.com/reproducible-containers/repro-get)
* [kpcyrd/pacman-bintrans: Experimental binary transparency for pacman with sigstore and rekor](https://github.com/kpcyrd/pacman-bintrans)
  * Also see: [kpcyrd/apt-swarm: 🥸 p2p gossip network for update transparency, based on pgp 🥸](https://github.com/kpcyrd/apt-swarm)
* [Open Policy Agent](https://www.openpolicyagent.org/)
* [netskopeoss/beam: Behavioral Evaluation of Application Metrics (BEAM) detects supply chain compromises by analyzing network traffic](https://github.com/netskopeoss/beam) using machine learning and SHAP explainability to identify malicious behavior patterns
* [Conftest](https://www.conftest.dev/examples/) allows to write tests against structured configuration data using the Open Policy Agent Rego query language: [here's an example](https://github.com/open-policy-agent/conftest/blob/master/examples/docker/policy/commands.rego)
* Several [pre-commit](https://pre-commit.com/hooks.html) hooks allow vulnerability checking right before dependency ingestion time into the codebase
  * e.g., [pyupio/safety: Safety checks your installed dependencies for known security vulnerabilities](https://github.com/pyupio/safety)
    * Or [npm-audit](https://docs.npmjs.com/cli/v8/commands/npm-audit)
      * Also see [snyk-labs/snync: Mitigate security concerns of Dependency Confusion supply chain security risks](https://github.com/snyk-labs/snync)
      * And [lirantal/lockfile-lint: Lint an npm or yarn lockfile to analyze and detect security issues](https://github.com/lirantal/lockfile-lint)
    * Or [requires.io | Monitor your dependencies](https://requires.io/)
    * Or [Brakeman Security Scanner](https://brakemanscanner.org/)
    * Or [trailofbits/pip-audit: Audits Python environments and dependency trees for known vulnerabilities](https://github.com/trailofbits/pip-audit)
      * Also see: [Dependabot alerts now surface if your code is calling a vulnerability](https://github.blog/2022-04-14-dependabot-alerts-now-surface-if-code-is-calling-vulnerability/)
      * And: [Use data-dist-info-metadata (PEP 658) to decouple resolution from downloading by cosmicexplorer · Pull Request #11111 · pypa/pip](https://github.com/pypa/pip/pull/11111)
    * Interesting Python-related project: [Project Thoth](https://thoth-station.ninja/), using Artificial Intelligence to analyse and recommend software stacks for Python applications
    * Or [Checkmarx/chainjacking: Find which of your go lang direct GitHub dependencies is susceptible to ChainJacking attack](https://github.com/Checkmarx/chainjacking)
    * Or [Cargo Vet](https://mozilla.github.io/cargo-vet/) and [crev-dev/cargo-crev: A cryptographically verifiable code review system for the cargo (Rust) package manager.](https://github.com/crev-dev/cargo-crev)
    * Not automated validation, but comprehensive guidance for Java with a few critical points relating to supply chain security: [Google Best Practices for Java Libraries](https://jlbp.dev/)
* Static analysis is often used at this stage in order to detect dependency acquisition, e.g.:
  * [Semgrep](https://semgrep.dev/)
    * [Getting started with Semgrep Supply Chain](https://semgrep.dev/docs/semgrep-sc/scanning-open-source-dependencies/)
    * Also see: [Catching Security Vulnerabilities With Semgrep](https://www.codedbrain.com/catching-security-vulnerabilities-with-semgrep/)
  * [graudit/signatures at master · wireghoul/graudit](https://github.com/wireghoul/graudit/tree/master/signatures)
  * [banyanops/collector: A framework for Static Analysis of Docker container images](https://github.com/banyanops/collector)
  * [quay/clair: Vulnerability Static Analysis for Containers](https://github.com/quay/clair)
  * [DataDog/guarddog: GuardDog is a CLI tool to Identify malicious PyPI and npm packages](https://github.com/datadog/guarddog)
  * [eliasgranderubio/dagda: a tool to perform static analysis of known vulnerabilities, trojans, viruses, malware &amp; other malicious threats in docker images/containers and to monitor the docker daemon and running docker containers for detecting anomalous activities](https://github.com/eliasgranderubio/dagda)
    * Half brilliant, half funny, full helpful: [kpcyrd/libredefender: Imagine the information security compliance guideline says you need an antivirus but you run Arch Linux](https://github.com/kpcyrd/libredefender)
  * [KICS - Keeping Infrastructure as Code Secure](https://kics.io/)
  * [tinkerbell/lint-install: Consistently install reasonable linter rules for open-source projects](https://github.com/tinkerbell/lint-install)
  * `hadolint` rules on package installation, e.g., [hadolint/README.md at d16f342c8e70fcffc7a788d122a1ba602075250d · hadolint/hadolint](https://github.com/hadolint/hadolint/blob/d16f342c8e70fcffc7a788d122a1ba602075250d/README.md#rules)
    * Also [dockerfile resource scans - checkov](https://www.checkov.io/5.Policy%20Index/dockerfile.html) from [bridgecrewio/checkov: Prevent cloud misconfigurations during build-time for Terraform, CloudFormation, Kubernetes, Serverless framework and other infrastructure-as-code-languages with Checkov by Bridgecrew.](https://github.com/bridgecrewio/checkov)
    * And: [xlab-si/iac-scan-runner: Service that scans your Infrastructure as Code for common vulnerabilities](https://github.com/xlab-si/iac-scan-runner)
    * And: [aws-samples/automated-security-helper](https://github.com/aws-samples/automated-security-helper)1
    * And: [GeekMasher/quibble](https://github.com/GeekMasher/quibble), a Rust-based security linter for Docker and Podman Compose files that checks for socket mounting, untrusted registries, hardcoded secrets and more. Read the [intro post](https://geekmasher.dev/sec/quibble/22-12-08--quibble-intro/)
* [Vulnerability Assessment | OpenSCAP portal](https://www.open-scap.org/features/vulnerability-assessment/)
* [Detecting Log4Shell with Wazuh](https://wazuh.com/blog/detecting-log4shell-with-wazuh/)
* [aquasecurity/starboard: Kubernetes-native security toolkit](https://github.com/aquasecurity/starboard)
  * [Get started with Kubernetes Security and Starboard](https://www.youtube.com/watch?v=QgctrpTpJec)
* [armosec/kubescape: Kubescape is a K8s open-source tool providing a multi-cloud K8s single pane of glass, including risk analysis, security compliance, RBAC visualizer and image vulnerabilities scanning.](https://github.com/armosec/kubescape)
  * Also: [kubescape Visual Studio Code extension](https://www.armosec.io/blog/find-kubernetes-security-issues-while-coding/)
* [ckotzbauer/vulnerability-operator: Scans SBOMs for vulnerabilities](https://github.com/ckotzbauer/vulnerability-operator)
* [chen-keinan/kube-beacon: Open Source runtime scanner for k8s cluster and perform security audit checks based on CIS Kubernetes Benchmark specification](https://github.com/chen-keinan/kube-beacon)
* [aquasecurity/kube-bench: Checks whether Kubernetes is deployed according to security best practices as defined in the CIS Kubernetes Benchmark](https://github.com/aquasecurity/kube-bench) and [aquasecurity/kube-hunter: Hunt for security weaknesses in Kubernetes clusters](https://github.com/aquasecurity/kube-hunter)
* [openclarity/kubeclarity: KubeClarity is a tool for detection and management of Software Bill Of Materials (SBOM) and vulnerabilities of container images and filesystems](https://github.com/openclarity/kubeclarity)
* [stackrox/stackrox: The StackRox Kubernetes Security Platform performs a risk analysis of the container environment, delivers visibility and runtime alerts, and provides recommendations to proactively improve security by hardening the environment.](https://github.com/stackrox/stackrox)
* [cloudquery/plugins/source/k8s/policies at main · cloudquery/cloudquery](https://github.com/cloudquery/cloudquery/tree/main/plugins/source/k8s/policies)
* [quarkslab/kdigger: Kubernetes focused container assessment and context discovery tool for penetration testing](https://github.com/quarkslab/kdigger)
* [ossillate-inc/packj: The vetting tool 🚀 behind our large-scale security analysis platform to detect malicious/risky open-source packages](https://github.com/ossillate-inc/packj) and [Packj | A vetting tool to avoid "risky" packages](https://packj.dev/)
* [doowon/sigtool: sigtool for signed PE files in GO](https://github.com/doowon/sigtool)
* [Introducing "safe npm", a Socket npm Wrapper - Socket](https://socket.dev/blog/introducing-safe-npm)
* [Introducing SafeDep vet 🚀 | SafeDep](https://safedep.io/blog/introducing-safedep-vet/)

Also see:

* [analysis-tools-dev/static-analysis: ⚙️ A curated list of static analysis (SAST) tools for all programming languages, config files, build tools, and more.](https://github.com/analysis-tools-dev/static-analysis/)
* [anderseknert/awesome-opa: A curated list of OPA related tools, frameworks and articles](https://github.com/anderseknert/awesome-opa)
* [JupiterOne/secops-automation-examples: Examples on how to maintain security/compliance as code and to automate SecOps using the JupiterOne platform.](https://github.com/JupiterOne/secops-automation-examples)
  * [How We Generate a Software Bill of Materials (SBOM) with CycloneDX](https://try.jupiterone.com/how-we-generate-a-software-bill-of-materials-sbom-with-cyclonedx)
* [Securing CICD pipelines with StackRox / RHACS and Sigstore](https://rcarrata.com/kubernetes/sign-images-acs-1/)
* Watch: [Do you trust your package manager?](https://www.youtube.com/watch?app=desktop&v=VfBShgNnQt4&feature=youtu.be) at Security Fest 2022

### Supply chain beyond libraries

And a few things to watch beyond libraries and software dependencies:

* [System Transparency | security architecture for bare-metal servers](https://system-transparency.org/)
* [Emulated host profiles in fwupd](https://blogs.gnome.org/hughsie/2022/07/29/emulated-host-profiles-in-fwupd/)
* [GNOME To Warn Users If Secure Boot Disabled, Preparing Other Firmware Security Help](https://www.phoronix.com/news/GNOME-Secure-Boot-Warning)
* [Kernel Self Protection Project - Linux Kernel Security Subsystem](https://kernsec.org/wiki/index.php/Kernel_Self_Protection_Project)
* [keylime/keylime: A CNCF Project to Bootstrap &amp; Maintain Trust on the Edge / Cloud and IoT](https://github.com/keylime/keylime)
* [parallaxsecond/parsec: Platform AbstRaction for SECurity service](https://github.com/parallaxsecond/parsec)
* [TPM Carte Blanche-resistant Boot Attestation](https://www.dlp.rip/tcb-attestation)

## Identity, signing and provenance

> This section includes: projects and discussions specifics to developer identity, OIDC, keyrings and related topics.

* Part of [sigstore](https://www.sigstore.dev/)
    * [Cosign](https://docs.sigstore.dev/cosign/overview)
    * [Fulcio](https://docs.sigstore.dev/fulcio/overview)
    * [Rekor](https://docs.sigstore.dev/rekor/overview)
    * Also see: [Kubernetes taps Sigstore to thwart open-source software supply chain attacks](https://www.zdnet.com/article/kubernetes-taps-sigstore-to-thwart-open-source-software-supply-chain-attacks/)
    * Sigstore-specific view of the [OpenSSF Landscape](https://landscape.openssf.org/sigstore)
    * Read: [Sigstore Bundle Format](https://www.trustification.io/blog/2023/01/13/sigstore-bundle-format/) walks through the structure of Sigstore's offline verification bundle, including signatures, certificates and Rekor inclusion proofs
    * [sigstore/model-transparency: Signing and verification for ML model integrity and provenance via Sigstore](https://github.com/sigstore/model-transparency) - extends model supply chain security to ML artifacts
* [cas - cas attestation service](https://cas.codenotary.com/)
* [Witness](https://witness.dev/) - [testifysec/witness: Witness is a pluggable framework for software supply chain risk management.  It automates, normalizes, and verifies software artifact provenance.](https://github.com/testifysec/witness)
  * Watch: [Securing the Supply Chain with Witness - Cole Kennedy, TestifySec](https://www.youtube.com/watch?v=cZD_4u7DZPM)
  * Also see: [testifysec/go-ima: go-ima is a tool that checks if a file has been tampered with.  It is useful in ensuring integrity in CI systems](https://github.com/testifysec/go-ima)
* [puerco/tejolote: A highly configurable build executor and observer designed to generate signed SLSA provenance attestations about build runs.](https://github.com/puerco/tejolote)
* [in-toto-run - GitHub Marketplace](https://github.com/marketplace/actions/in-toto-run) and [in-toto/github-action: in-toto provenance github action](https://github.com/in-toto/github-action)
* [kusaridev/spector](https://github.com/kusaridev/spector) is a Rust tool and library for strict generation, validation and verification of supply chain metadata documents, supporting SLSA 1.0 Provenance and in-toto 1.0 Statement. Read the [announcement](https://www.kusari.dev/blog/kusari-open-sources-spector)
* [General availability of SLSA3 Generic Generator for GitHub Actions](https://slsa.dev/blog/2022/08/slsa-github-workflows-generic-ga)
  * [slsa-framework/slsa-github-generator: Language-agnostic SLSA provenance generation for Github Actions](https://github.com/slsa-framework/slsa-github-generator)
  * Also see: [Attestation Crafting | ChainLoop documentation](https://docs.chainloop.dev/getting-started/attestation-crafting)
* [technosophos/helm-gpg: Chart signing and verification with GnuPG for Helm.](https://github.com/technosophos/helm-gpg)
* [cashapp/pivit](https://github.com/cashapp/pivit) is a command line tool for managing x509 certificates stored on smart cards with PIV applet support that is fully compatible with `git`
* [notaryproject/notary: Notary is a project that allows anyone to have trust over arbitrary collections of data](https://github.com/notaryproject/notary)
  * [notaryproject/roadmap: Roadmap for NotaryV2](https://github.com/notaryproject/roadmap)
  * [notaryproject/notation: Notation is a project to add signatures as standard items in the registry ecosystem, and to build a set of simple tooling for signing and verifying these signatures. Based on Notary V2 standard.](https://github.com/notaryproject/notation)
  * [notaryproject/tuf: The Update Framework for OCI Registries](https://github.com/notaryproject/tuf)
    * Also see [vmware-labs/repository-editor-for-tuf: Command line tool for editing and maintaining a TUF repository](https://github.com/vmware-labs/repository-editor-for-tuf)
    * Also see [How to easily try out TUF + in-toto](https://badhomb.re/ci/security/2020/05/01/tuf-in-toto.html)
    * Check out [Python-TUF reaches version 1.0.0](https://ssl.engineering.nyu.edu/blog/2022-02-21-tuf-1_0_0)
    * Related project: [werf/trdl: The universal solution for delivering your software updates securely from a trusted The Update Framework (TUF) repository.](https://github.com/werf/trdl)
    * Read: [Secure Software Updates via TUF — Part 2](https://medium.com/@mulgundmath/secure-software-updates-via-tuf-part-2-412c6a2b10ab)
* [deislabs/ratify: Artifact Ratification Framework](https://github.com/deislabs/ratify)
* [latchset/tang: Tang binding daemon](https://github.com/latchset/tang)
* [ietf-rats - Overview](https://github.com/ietf-rats)
* [An exposed apt signing key and how to improve apt security](https://blog.cloudflare.com/dont-use-apt-key/)
* See [Issue #21 · testifysec/witness](https://github.com/testifysec/witness/issues/21#issuecomment-991774080) for a succinct description of how [testifysec/witness: Witness is a pluggable framework for software supply chain risk management.  It automates, normalizes, and verifies software artifact providence.](https://github.com/testifysec/witness/) deals with attestation chains 
  * Another [witness example with GitLab](https://gitlab.com/testifysec/demos/witness-demo)
* [Allow using SSH keys to sign commits · Discussion #7744 · github/feedback](https://github.com/github/feedback/discussions/7744#discussioncomment-1794438)
* Read: [Introducing "Trusted Publishers"](https://blog.pypi.org/posts/2023-04-20-introducing-trusted-publishers/) on PyPI's use of OpenID Connect for short-lived, tokenless publishing from GitHub Actions, eliminating the need for long-lived API tokens
* [aws-solutions/verifiable-controls-evidence-store: This repository contains the source code of the Verifiable Controls Evidence Store solution](https://github.com/aws-solutions/verifiable-controls-evidence-store)
* Read: [Monitoring the kernel.org Transparency Log for a year](https://linderud.dev/blog/monitoring-the-kernel.org-transparency-log-for-a-year/)
* Read: [Guide to Rekor Monitor and Its Integration with Red Hat Trusted Artifact Signer](https://www.redhat.com/en/blog/guide-rekor-monitor-and-its-integration-red-hat-trusted-artifact-signer) (Red Hat), covering transparency log integrity verification with continuous monitoring and Prometheus metrics
* Read: [Catching Malicious Package Releases Using a Transparency Log](https://blog.trailofbits.com/2025/12/12/catching-malicious-package-releases-using-a-transparency-log/) (Trail of Bits), explaining how rekor-monitor detects compromised signing identities and malicious releases via Rekor transparency logs
* Also read: [Software Distribution Transparency and Auditability](https://arxiv.org/abs/1711.07278)
* [paragonie/libgossamer: Public Key Infrastructure without Certificate Authorities, for WordPress and Packagist](https://github.com/paragonie/libgossamer)
  * Read: [Solving Open Source Supply Chain Security for the PHP Ecosystem](https://paragonie.com/blog/2022/01/solving-open-source-supply-chain-security-for-php-ecosystem)
* [johnsonshi/image-layer-provenance](https://github.com/johnsonshi/image-layer-provenance), a PoC for Image Layer Provenance and Manifest Layer History
* [oras-project/artifacts-spec](https://github.com/oras-project/artifacts-spec/)
* [recipy/recipy: Effortless method to record provenance in Python](https://github.com/recipy/recipy)
* [spiffe/spire: The SPIFFE Runtime Environment](https://github.com/spiffe/spire)
* [Fraunhofer-SIT/charra: Proof-of-concept implementation of the &quot;Challenge/Response Remote Attestation&quot; interaction model of the IETF RATS Reference Interaction Models for Remote Attestation Procedures using TPM 2.0.](https://github.com/Fraunhofer-SIT/charra)
* [google/trillian: A transparent, highly scalable and cryptographically verifiable data store.](https://github.com/google/trillian)
* [Artifactory - Universal Artifact Management](https://jfrog.com/artifactory/)
* [pyrsia/pyrsia: Decentralized Package Network](https://github.com/pyrsia/pyrsia)
* [transmute-industries/verifiable-actions: Workflow tools for Decentralized Identifiers &amp; Verifiable Credentials](https://github.com/transmute-industries/verifiable-actions/tree/main)
* [IOTA Notarization](https://www.iota.org/products/notarization) is an open-source toolkit for anchoring, updating and verifying data integrity on a decentralized ledger, supporting locked (immutable) and dynamic notarization modes. See [iotaledger](https://github.com/iotaledger) on GitHub
* Watch: [Privacy-preserving Approaches to Transparency Logs](https://www.youtube.com/watch?v=UrLdEYVASak)

## Frameworks and best practice references

> This section includes: reference architectures and authoritative compilations of supply chain attacks and the emerging categories.

* [in-toto | A framework to secure the integrity of software supply chains](https://in-toto.io/)
* [Supply chain Levels for Software Artifacts](https://slsa.dev/) or SLSA (salsa) is a security framework, a check-list of standards and controls to prevent tampering, improve integrity, and secure packages and infrastructure in your projects, businesses or enterprises. 
  * Great read: [SLSA | CloudSecDocs](https://cloudsecdocs.com/devops/pipelines/supply_chain/slsa/)
  * Another L50 read: [Building trust in our software supply chains with SLSA](https://blog.chainguard.dev/building-trust-in-our-software-supply-chains-with-slsa/)
  * Read: [SLSA for Success: Using SLSA to help achieve NIST’s SSDF](https://slsa.dev/blog/2022/06/slsa-ssdf) and [All about that Base(line): How Cybersecurity Frameworks are Evolving with Foundational Guidance](https://slsa.dev/blog/2022/07/slsa-foundational-framework)
    * Also, a [framework mapping](https://docs.google.com/spreadsheets/d/1P_xxMlyF5iPV51CqIk8_EhI57aR6wf1Gkrg8sRHBMMQ/edit?usp=sharing) put together by [Red Hat](https://www.redhat.com/en/blog/SLSA-framework-measuring-supply-chain-security-maturity)
  * [A Practical Guide to the SLSA Framework](https://fossa.com/blog/practical-guide-slsa-framework/) by FOSSA
  * Read: [Securing Gitpod's Software Supply Chain with SLSA](https://www.gitpod.io/blog/securing-the-software-supply-chain-at-gitpod-with-slsa)
  * Read: [A First Step to Attaining SLSA Level 3 on GitHub](https://blogs.vmware.com/opensource/2022/08/02/a-first-step-to-attaining-slsa-level-3-on-github/)
  * And a [pattern search across GitHub](https://cs.github.com/?scopeName=All+repos&scope=&q=%22uses%3A+slsa-framework%2Fslsa-github-generator%2F.github%2Fworkflows%2F%22+path%3A**.yml+NOT+org%3Aslsa-framework+NOT+org%3Aasraa+NOT+org%3Alaurentsimon+NOT+org%3Aazeemshaikh38+NOT+org%3Asethmlarson+NOT+org%3Alukehinds) for inspiration (thanks [@infernosec](https://twitter.com/infernosec/status/1559937819128127488))
* [OWASP Application Security Verification Standard](https://owasp.org/www-project-application-security-verification-standard/), esp. _V14 - Configuration_
* [OWASP/Software-Component-Verification-Standard: Software Component Verification Standard (SCVS)](https://github.com/OWASP/Software-Component-Verification-Standard)
  * Also see: [OWASP SCVS BOM Maturity Model](https://scvs.owasp.org/bom-maturity-model/), a formalized taxonomy for evaluating bill of materials capabilities and supporting organizational policies
* [CREST launches OWASP Verification Standard (OVS)](https://www.crest-approved.org/crest-launches-owasp-verification-standard-ovs/)
* SAFECODE's [Fundamental Practices for Secure Software Development, Third Edition](https://safecode.org/uncategorized/fundamental-practices-secure-software-development/), esp. _Manage Security Risk Inherent in the Use of Third-party Components_
* [SSF | The Secure Software Factory](https://thesecuresoftwarefactory.github.io/ssf/) and [mlieberman85/supply-chain-examples](https://github.com/mlieberman85/supply-chain-examples)
  * Related: [A MAP for Kubernetes supply chain security](https://www.cncf.io/blog/2022/04/12/a-map-for-kubernetes-supply-chain-security/)
* [Software Supply Chain Risk Management | BSIMM](https://www.bsimm.com/about/bsimm-for-vendors.html)
* [microsoft/scim: Supply Chain Integrity Model](https://github.com/microsoft/SCIM)
  * Also see: [Supply Chain Integrity, Transparency, and Trust (scitt)](https://datatracker.ietf.org/group/scitt/about/) and [What Is SCITT](https://scitt.io/)
* [SecureStackCo/visualizing-software-supply-chain: A visual taxonomy and contextual mapping of software supply chain components](https://github.com/SecureStackCo/visualizing-software-supply-chain) organized across 10 stages (People, Local Requirements, Source Code, Integration, Deployment, Runtime, Hardware, DNS, Services, Cloud) with examples of technologies and vendors
* [Goodbye SDLC, Hello SSDF! What is the Secure Software Development Framework?](https://blog.chainguard.dev/goodbye-sdlc-hello-ssdf-what-is-the-secure-software-development-framework/)
  * Also [Comply with NIST's secure software supply chain framework with GitLab](https://about.gitlab.com/blog/2022/03/29/comply-with-nist-secure-supply-chain-framework-with-gitlab/)
* The _Supply Chain Risk Management_ section of [SP 800-53 Rev. 5, Security and Privacy Controls for Info Systems and Organizations | CSRC](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final), also see [center-for-threat-informed-defense/attack-control-framework-mappings: Security control framework mappings to MITRE ATT&CK](https://github.com/center-for-threat-informed-defense/attack-control-framework-mappings)
* [SP 800-161 Rev. 1, C-SCRM Practices for Systems and Organizations | CSRC](https://csrc.nist.gov/publications/detail/sp/800-161/rev-1/final)
* [npm Best Practices Guide](https://github.com/ossf/package-manager-best-practices/blob/main/published/npm.md) (OpenSSF) - Features and recommendations on using npm safely
* [Principles for Package Repository Security](https://repos.openssf.org/principles-for-package-repository-security) (OpenSSF) - Taxonomy and security maturity levels for package repositories across authentication, authorization, general capabilities, and CLI tooling
* [CIS Software Supply Chain Security Guide](https://github.com/aquasecurity/chain-bench/blob/main/docs/CIS-Software-Supply-Chain-Security-Guide-v1.0.pdf)
* [microsoft/oss-ssc-framework: Open Source Software Secure Supply Chain Framework](https://github.com/microsoft/oss-ssc-framework)
* GitHub's [Implementing software security in open source](https://github.com/readme/guides/sigstore-software-security)
* Previously referenced: [Google Best Practices for Java Libraries](https://jlbp.dev/)
* MITRE's [System of Trust](https://sot.mitre.org/framework/system_of_trust.html)
* [Securing the Software Supply Chain for Developers](https://media.defense.gov/2022/Sep/01/2003068942/-1/-1/0/ESF_SECURING_THE_SOFTWARE_SUPPLY_CHAIN_DEVELOPERS.PDF) was published by the National Security Agency (NSA), Cybersecurity and Infrastructure Security Agency (CISA), and the Office of the Director of National Intelligence (ODNI) under the Enduring Security Framework (ESF) initiative
* Read: [Government's Role in Increasing Software Supply Chain Security — A Toolbox for Policy Makers](https://www.interface-eu.org/publications/governments-role-increasing-software-supply-chain-security-toolbox-policy-makers) from Interface-EU, a three-level policy framework spanning secure development practices, CVD guidance, SBOMs, standards, procurement requirements, and liability regimes
* OpenSSF's [Concise Guide for Developing More Secure Software 2022-09-01](https://github.com/ossf/wg-best-practices-os-developers/blob/main/docs/Concise-Guide-for-Developing-More-Secure-Software.md#readme)
* Chris Hughes on the NSA Recommended Practices for Developers: [Securing the Software Supply Chain](https://medium.com/@chris.hughes_11070/securing-the-software-supply-chain-d3426d36150d)
* Read: [Elements of an Effective Software Supply Chain Strategy](https://www.informationweek.com/software-services/elements-of-an-effective-software-supply-chain-strategy) proposes 12 elements for software supply chain risk management spanning asset inventory, SBOM, provenance, attestation, compliance and governance

Also see:

* [Zero Trust the Hard Way](https://www.youtube.com/watch?app=desktop&v=PMhPWGRzIzM), Kelsey Hightower
* [KubePhilly March 2022-  A Look At The Kubernetes SLSA Compliance Project](https://www.youtube.com/watch?v=KV6kfO6gtho)
* [Supply Chain Risk Management](https://blog.aquia.us/blog/2022-03-06-supply-chain-risk-mgmt/)

## Build techniques

> This section includes: reproducible builds, hermetic builds, bootstrappable builds, special considerations for CI/CD systems, best practices building artifacts such as OCI containers, etc.

* [Reproducible Builds](https://reproducible-builds.org/), particularly the [Documentation](https://reproducible-builds.org/docs/)
  * [r-b ecosytem mapping](https://pad.riseup.net/p/rbecosystemmapping-keep)
  * [Reproducible Builds / reprotest](https://salsa.debian.org/reproducible-builds/reprotest)
  * [Is NixOS Reproducible?](https://r13y.com/)
* [Bootstrappable Builds (GNU Mes Reference Manual)](https://www.gnu.org/software/mes/manual/html_node/Bootstrappable-Builds.html)
  * Also read [Bootstrappable builds](https://lwn.net/Articles/841797/) from LWN
* [tektoncd/chains: Supply Chain Security in Tekton Pipelines](https://github.com/tektoncd/chains)
  * [Verifiable Supply Chain Metadata for Tekton - CD Foundation](https://cd.foundation/blog/2021/06/18/verifiable-supply-chain-metadata-for-tekton/)
* [google/santa: A binary authorization system for macOS](https://github.com/google/santa)
* [fepitre/package-rebuilder: Standalone orchestrator for rebuilding Debian, Fedora and Qubes OS packages in order to generate `in-toto` metadata which can be used with `apt-transport-in-toto` or `dnf-plugin-in-toto` to validate reproducible status.](https://github.com/fepitre/package-rebuilder)
* [kpcyrd/rebuilderd-debian-buildinfo-crawler: Reproducible Builds: Scraper/Parser for https://buildinfos.debian.net into structured data](https://github.com/kpcyrd/rebuilderd-debian-buildinfo-crawler)
  * Also see [Reproducible Builds: Debian and the case of the missing version string - vulns.xyz](https://vulns.xyz/2022/01/debian-missing-version-string/)
* [kpcyrd/rebuilderd: Independent verification of binary packages - reproducible builds](https://github.com/kpcyrd/rebuilderd)
* [tag-security/sscsp.md at main · cncf/tag-security](https://github.com/cncf/tag-security/blob/main/supply-chain-security/supply-chain-security-paper/sscsp.md)
* [defenseunicorns/zarf: DevSecOps for Air Gap & Limited-Connection Systems. https://zarf.dev/](https://github.com/defenseunicorns/zarf)
* [Lockheed Martin / hoppr / hoppr](https://gitlab.com/lmco/hoppr/hoppr) is a CLI framework for defining, validating, and transferring dependencies between environments
  * Example using SBOM as an input: [Inputs - Hoppr](https://lmco.gitlab.io/hoppr/hoppr/getting_started/inputs.html#cyclonedx-sboms)
* On instrumenting runners:
  * Keep an eye on [Draft: POC Witness Runner integration (!1) · Merge requests · testifysec / gitlab-runner](https://gitlab.com/testifysec/gitlab-runner/-/merge_requests/1) for GitLab runners
  * Also, [edgelesssys/constellation: Constellation is the first Confidential Kubernetes. Constellation shields entire Kubernetes clusters from the (cloud) infrastructure using confidential computing.](https://github.com/edgelesssys/constellation)
* [reposaur/reposaur: Open source compliance tool for development platforms.](https://github.com/reposaur/reposaur)
* [buildsec/frsca](https://github.com/buildsec/frsca) is an implementation of the CNCF's Secure Software Factory Reference Architecture. It is also intended to follow SLSA requirements closely and generate in-toto attesttations for SLSA provenance predicates.
* [chainloop-dev/chainloop: Chainloop is an open source software supply chain control plane, a single source of truth for artifacts plus a declarative attestation crafting process.](https://github.com/chainloop-dev/chainloop)
  * Also see: [Software Supply Chain Attestation the Easy Way](https://docs.chainloop.dev/blog/software-supply-chain-attestation-easy-way) from the Chainloop documentation
  * Read: [Attestation concepts](https://docs.chainloop.dev/concepts/attestations) covers the attestation lifecycle (`init`, `add`, `push`) and Sigstore bundle format used by Chainloop
* [aquasecurity/chain-bench: an open-source tool for auditing your software supply chain stack for security compliance](https://github.com/aquasecurity/chain-bench) implementing checks for [CIS 1.0 | Vulnerability Database | Aqua Security](https://avd.aquasec.com/compliance/softwaresupplychain/cis-1.0/)
* [ossf/allstar: GitHub App to set and enforce security policies](https://github.com/ossf/allstar)
* [kusaridev/skootrs](https://github.com/kusaridev/skootrs) is a CLI tool for creating secure-by-design/default source repos with security best practices built in
* [MediaMarktSaturn/technolinator](https://github.com/MediaMarktSaturn/technolinator), a GitHub App for pull-request vulnerability analysis and SBOM creation/upload to Dependency-Track, wrapping CDXGen, SBOMQS, and dep-scan/Grype
* [scribe-public/gitgat: Evaluate source control (GitHub) security posture](https://github.com/scribe-public/gitgat)
* [Legit-Labs/legitify: Detect and remediate misconfigurations and security risks across all your GitHub and GitLab assets](https://github.com/Legit-Labs/legitify)
* [crashappsec/github-analyzer: A tool to check the security settings of Github Organizations.](https://github.com/crashappsec/github-analyzer)
* [wspr-ncsu/github-actions-security-analysis](https://github.com/wspr-ncsu/github-actions-security-analysis) from [Characterizing the Security of Github CI Workflows | USENIX](https://www.usenix.org/conference/usenixsecurity22/presentation/koishybayev)
* [oss-reproducible](https://github.com/microsoft/OSSGadget/tree/main/src/oss-reproducible) - Measures the reproducibility of a package based on its purported source. Part of [OSS Gadget](https://github.com/microsoft/OSSGadget)
* [jart/landlock-make: Sandboxing for GNU Make has never been easier](https://github.com/jart/landlock-make)
  * Read: [Using Landlock to Sandbox GNU Make](https://justine.lol/make/)
* [veraison/veraison: Project Veraison will build software components that can be used to build Attestation Verification Services](https://github.com/veraison/veraison)
* [Changelog](https://www.pantsbuild.org/docs/changelog) for [Pants 2: The ergonomic build system](https://www.pantsbuild.org/)
* [Bazel](https://bazel.build/) is an open source build and test tool similar to Make, Maven, and Gradle
* [GoogleContainerTools/kaniko: Build Container Images In Kubernetes](https://github.com/GoogleContainerTools/kaniko)
* [sethvargo/ratchet: A tool for securing CI/CD workflows with version pinning.](https://github.com/sethvargo/ratchet)
* [Pinning GitHub Actions](https://pin-gh-actions.kammel.dev/) guide with statistics on SHA pinning adoption and tools like Frizbee for migration and Renovate for automated updates
* [buildsec/vendorme](https://github.com/buildsec/vendorme) improves the developer workflow by giving you one single place to manage any vendored dependencies, and ensures that those are validated properly to improve the security around your supply chain
* [eellak/build-recorder](https://github.com/eellak/build-recorder)
  * Also see: [FOSDEM 2023 - Build recorder: a system to capture detailed information](https://fosdem.org/2023/schedule/event/sbom_build_recorder/)
* [rust-secure-code/cargo-auditable: Embed the Cargo dependency tree in your Rust binaries](https://github.com/rust-secure-code/cargo-auditable), enabling vulnerability auditing of compiled Rust binaries with zero bookkeeping; supported by cargo-audit, Trivy, Grype, and other tools

Also see:

* The [reproducible-builds](https://github.com/topics/reproducible-builds) topic on GitHub
* [Dependency management](https://cloud.google.com/artifact-registry/docs/dependencies) as part of Google Cloud's Artifact Registry documentation
* [Security hardening for GitHub Actions](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
  * And: [step-security/harden-runner: Security agent for GitHub-hosted runner: block egress traffic &amp; detect code overwrite to prevent breaches](https://github.com/step-security/harden-runner)
  * And: [StepSecurity Action Advisor](https://app.stepsecurity.io/action-advisor), a tool that scores GitHub Actions for security and suggests maintained alternatives
* [Handling build-time dependency vulnerabilities](https://hackmd.io/@VOkN52x7RbeXS-3vr4XOgg/BJBDNYK0F) from [Create guidance on triaging build time dependency vulnerabilities · Issue #855 · cncf/tag-security](https://github.com/cncf/tag-security/issues/855)
* [Code Sight](https://www.synopsys.com/software-integrity/code-sight.html)
* [cider-security-research/cicd-goat: A deliberately vulnerable CI/CD environment. Learn CI/CD security through multiple challenges.](https://github.com/cider-security-research/cicd-goat)
  * And: [step-security/attack-simulator: Simulate past supply chain attacks such as SolarWinds, Codecov, and ua-parser-js](https://github.com/step-security/attack-simulator)
* Read: [What Makes a Build Reproducible, Part 2](https://blogs.vmware.com/opensource/2022/07/14/what-makes-a-build-reproducible-part-2/)
* Read: [Building a Secure Software Supply Chain with GNU Guix](https://programming-journal.org/2023/7/1/)
* [alecmocatta/build_id: Obtain a UUID uniquely representing the build of the current binary.](https://github.com/alecmocatta/build_id)
* Read: [On Omitting Commits and Committing Omissions: Preventing Git Metadata Tampering That (Re)introduces Software Vulnerabilities](https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/torres-arias)
* Read: [Reproducible Builds: Break a log, good things come in trees](https://bora.uib.no/bora-xmlui/handle/1956/20411)
* [Secure Your Software Factory with melange and apko](https://www.chainguard.dev/unchained/secure-your-software-factory-with-melange-and-apko)
  * On the `apko` pattern, see [Shopify/hansel](https://github.com/Shopify/hansel)
* [kpcyrd/archlinux-inputs-fsck: Lint repository of PKGBUILDs for cryptographically pinned inputs](https://github.com/kpcyrd/archlinux-inputs-fsck)

## Talks, articles, media coverage and other reading

### Getting started and staying fresh

* A few resources, in addition to this repository, that can help keep up with news and announcements:
  * An RSS feed maintained by [@bureado](https://github.com/bureado) with a mix of open source security, DevSecOps, AppSec and supply chain security news: [corner-security](https://www.inoreader.com/stream/user/1005644984/tag/corner-security)
  * [tl;dr sec Newsletter](https://tldrsec.com/newsletter/)
  * [Past Issues | CloudSecList](https://cloudseclist.com/past-issues/)
  * [News - reproducible-builds.org](https://reproducible-builds.org/news/)
  * A great compilation of reads, context and learning materials: [chainguard-dev/ssc-reading-list: A reading list for software supply-chain security.](https://github.com/chainguard-dev/ssc-reading-list)
  * A visual reference by Enso Security: [AppSec Map](https://appsecmap.com/MyMap)
  * A similar one: [Jetstack | The Software Supply Chain Toolkit](https://jetstack.io/software-supply-chain/)
  * [wg-security-tooling/guide.md at main · ossf/wg-security-tooling](https://github.com/ossf/wg-security-tooling/blob/main/guide.md) from [ossf/wg-security-tooling: OpenSSF Security Tooling Working Group](https://github.com/ossf/wg-security-tooling#active-projects)
  * [A toolbox for a secure software supply chain](https://blog.chainguard.dev/a-toolbox-for-a-secure-software-supply-chain/) from Chainguard
  * The [Technology](https://snyk.io/series/devsecops/technology/) chapter in Snyk's DevSecOps series
  * A helpful list of acronyms: [Acronyms | OpenSCAP portal](https://www.open-scap.org/resources/acronyms/)
  * [slsa/terminology.md at main · slsa-framework/slsa](https://github.com/slsa-framework/slsa/blob/main/docs/_spec/v0.1/terminology.md)
  * [tag-security/cloud-native-security-lexicon.md at main · cncf/tag-security](https://github.com/cncf/tag-security/blob/main/security-lexicon/cloud-native-security-lexicon.md)
  * Watch: [How to start learning about Supply Chain Security](https://www.youtube.com/watch?v=vFLmm8NnHFg)
  * Watch: [Open Source Supply Chain Security: A Visualization of the Checkmarx Solution](https://www.youtube.com/watch?v=MIus0_o72hE), plus the Checkmarx channel on YouTube has excellent explanatory videos for tactics, techniques and procedures in the supply chain security domain, for example: [Large Scale Campaign Created Fake GitHub Projects Clones with Fake Commit Added Malware](https://www.youtube.com/watch?v=VQ1blNH3qGM)

And a collection of reads and listens, ranging from insightful blog posts, explainers/all-rounders and some long-form analysis (we've tried to keep deep dive reads scoped to other sections)

* [Secure Software Development Fundamentals Courses - Open Source Security Foundation](https://openssf.org/training/courses/)
  * [Securing Your Software Supply Chain with Sigstore](https://www.edx.org/course/securing-your-software-supply-chain-with-sigstore)
* [Census II of Free and Open Source Software — Application Libraries](https://linuxfoundation.org/wp-content/uploads/LFResearch_Harvard_Census_II.pdf)
* [“Chain”ging the Game - how runtime makes your supply chain even more secure](https://sysdig.com/blog/chainging-the-game/)
* [How to attack cloud infrastructure via a malicious pull request](https://goteleport.com/blog/hack-via-pull-request/)
* [Introducing StepSecurity Developer MDM](https://www.stepsecurity.io/blog/introducing-stepsecurity-developer-mdm-protecting-developer-machines-from-supply-chain-attacks), on protecting developer machines and AI coding agents from supply chain attacks targeting credentials, IDE extensions and local dependencies
* [The Challenges of Securing the Open Source Supply Chain](https://thenewstack.io/the-challenges-of-securing-the-open-source-supply-chain/)
* [What is a Software Supply Chain Attestation - and why do I need it?](https://www.testifysec.com/blog/what-is-a-supply-chain-attestation/)
* [Open Policy Agent 2021, Year in Review](https://blog.openpolicyagent.org/open-policy-agent-2021-year-in-review-f334244868e0)
* [Reproducibility · Cloud Native Buildpacks](https://buildpacks.io/docs/features/reproducibility/) and [Buildpacks and SBOM Integration Opportunities](https://zt.dev/posts/buildpacks-sbom-opportunities/)
* [The state of software bill of materials: SBOM growth could bolster software supply chains](https://venturebeat.com/2022/02/02/the-state-of-software-bill-of-materials-sbom-growth-could-bolster-software-supply-chains/)
* [Secure Your Software Supply Chain with New VMware Tanzu Application Platform Capabilities](https://tanzu.vmware.com/content/blog/secure-software-supply-chain-vmware-tanzu-application-platform)
  * [Secure Software Supply Chains](https://tanzu.vmware.com/developer/learningpaths/secure-software-supply-chain/)
* A few resources to understand supply chain compromises:
  * [Supply Chain Compromise - attackics](https://collaborate.mitre.org/attackics/index.php/Technique/T0862#:~:text=Supply%20chain%20compromise%20is%20the,receipt%20by%20the%20end%20consumer.&text=This%20may%20involve%20the%20compromise,third%20party%20or%20vendor%20websites.)
  * [tag-security/supply-chain-security/compromises at main · cncf/tag-security](https://github.com/cncf/tag-security/tree/main/supply-chain-security/compromises)
  * [IQTLabs/software-supply-chain-compromises: A dataset of software supply chain compromises. Please help us maintain it!](https://github.com/IQTLabs/software-supply-chain-compromises)
  * [Atlantic Council Software Supply Chain Security — The Dataset](https://www.atlanticcouncil.org/content-series/cybersecurity-policy-and-strategy/software-supply-chain-security-the-dataset/), an interactive dashboard and downloadable dataset of 250+ software supply chain attacks and disclosures, filterable by scale, timing, actors, codebase, and attack vectors
  * [Taxonomy of Attacks on Open-Source Software Supply Chains](https://arxiv.org/abs/2204.04008) and [Risk Explorer for Software Supply Chains](https://sap.github.io/risk-explorer-for-software-supply-chains/)
    * Endor Labs' version: [Risk Explorer for Software Supply Chains](https://riskexplorer.endorlabs.com/)
    * See also: [SAP-samples/risk-explorer-execution-pocs](https://github.com/SAP-samples/risk-explorer-execution-pocs), runnable PoC implementations demonstrating how 3rd-party dependencies can achieve arbitrary code execution at install time and runtime across multiple ecosystems (Python, JavaScript, Ruby, PHP, Rust, Go, Java)
    * Also see a classic, [Backstabber's Knife Collection: A Review of Open Source Software Supply Chain Attacks](https://arxiv.org/abs/2005.09535)
  * [Towards Measuring Supply Chain Attacks on Package Managers for Interpreted Languages](https://arxiv.org/pdf/2002.01139.pdf)
  * The [Software Supply Chain Security Threat Landscape](https://www.linkedin.com/posts/tzachi-zornstain_august-supply-chain-summary-report-activity-6975045859688239104-adsU/?utm_source=share) dispatches from Checkmarx are often fresh reading
  * [ossf/oss-compromises: Archive of various open source security compromises](https://github.com/ossf/oss-compromises)
  * Python-specific example: [Bad actors vs our community: detecting software supply chain...](https://www.youtube.com/watch?app=desktop&v=Rcuqn56uCDk&feature=youtu.be) by Ajinkya Rajput and Ashish Bijlani
  * A comprehensive all rounder: [Protect Yourself Against Supply Chain Attacks - Rob Bos - NDC Security 2022](https://www.youtube.com/watch?v=00R1JGBQEJg)
  * Not supply chain security specific, but worth tracking: [PayDevs/awful-oss-incidents: 🤬 A categorized list of incidents caused by unappreciated OSS maintainers or underfunded OSS projects. Feedback welcome!](https://github.com/PayDevs/awful-oss-incidents)
* [Improving TOFU (trust on first use) With Transparency](https://dlorenc.medium.com/improving-tofu-with-transparency-da674aa2879d)
* Reports:
  * [2022 State of Cloud Native Security Report - Palo Alto Networks](https://www.paloaltonetworks.com/state-of-cloud-native-security)
  * [2022 Software Supply Chain Security Report • Anchore](https://anchore.com/software-supply-chain-security-report-2022/)
* End-to-end demos and examples:
  * [goreleaser/supply-chain-example: Example goreleaser + github actions config with keyless signing and SBOM generation](https://github.com/goreleaser/supply-chain-example)
  * [Improve supply chain security with GitHub actions, Cosign, Kyverno and other open source tools](https://www.cloudnative.quest/posts/security/2022/01/01/improve-supply-chain-security-with-github-actions-and-open-source-tools/)
* [Using SARIF to Extend Analysis of SAST Tools](https://blogs.grammatech.com/using-sarif-to-extend-analysis-of-sast-tools)
* GitLab's [Software Supply Chain Security](https://about.gitlab.com/solutions/supply-chain/) section
  * Also read GitLab's [Software Supply Chain Security Direction](https://about.gitlab.com/direction/supply-chain/)
* GitHub's [SARIF support for code scanning](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning)
* [Driving Developer Productivity via Automated Dependency Tracking](https://developer.gs.com/blog/posts/driving-developer-productivity-via-automated-dependency-tracking)
* [Code scanning finds more vulnerabilities using machine learning](https://github.blog/2022-02-17-code-scanning-finds-vulnerabilities-using-machine-learning/)
* [Securing Open Source Software at the Source](https://www.plaintextgroup.com/reports/securing-open-source-software-at-the-source)
* [Security: The Value of SBOMs](https://fluxcd.io/blog/2022/02/security-the-value-of-sboms/)
* [Why SBOMS & Security Scanning Go Together - Upstream: The Software Supply Chain Security Podcast presented by Anchore](https://www.buzzsprout.com/1913318/10096487)
* [SBOMs in the Windows Supply Chain](https://s3-us-west-1.amazonaws.com/groupsioattachments/19482/98065190/1665/0?AWSAccessKeyId=AKIAJECNKOVMCCU3ATNQ&Expires=1682372170&Signature=x0o52XZ1FYr5QpNHAg8hb49mFcY%3D&response-content-disposition=inline%3B+filename%3D%22SBOMs%2520in%2520the%2520Windows%2520Supply%2520Chain.pdf%22), from the [SPDX User Group](https://lists.spdx.org/g/spdx/message/1679)
* [Whose Sign Is It Anyway?](https://www.youtube.com/watch?v=psTh2xOvVJI) - Marina Moore, NYU & Matthew Riley, Google
* [Binary Authorization for Borg: how Google verifies code provenance and implements code identity](https://cloud.google.com/docs/security/binary-authorization-for-borg)
* [Application Security Weekly (Video) on Apple Podcasts](https://podcasts.apple.com/us/podcast/application-security-weekly-video/id1338908396)
* [How to prioritize the improvement of open source software security](https://www.brookings.edu/techstream/how-to-prioritize-the-improvement-of-open-source-software-security/)
  * And [Strengthening digital infrastructure: A policy agenda for free and open source software](https://www.brookings.edu/research/strengthening-digital-infrastructure-a-policy-agenda-for-free-and-open-source-software/)
* [Software Supply Chain Security Turns to Risk Mitigation](https://www.nationaldefensemagazine.org/articles/2022/3/8/software-supply-chain-security-turns-to-risk-mitigation)
* [Reproducible Builds: Increasing the Integrity of Software Supply Chains](https://arxiv.org/abs/2104.06020)
* [sigstore/community: General sigstore community repo](https://github.com/sigstore/community#slack)
* [CycloneDX Use Cases](https://cyclonedx.org/use-cases/)
  * Listen: [#6: Steve Springett: CycloneDX and the Future of SBOMs - Cybellum](https://cybellum.com/podcast/6-steve-springett-cyclonedx-and-the-future-of-sboms/)
  * Watch: [CycloneDX and the Cloud](https://www.youtube.com/watch?v=ctBS2lfd020) from OWASP CycloneDX
* [Building a Sustainable Software Supply Chain](https://fossa.com/blog/building-sustainable-software-supply-chain/), particularly the section: "The Software Supply Chain Sustainability Maturity Model"
* [Dependency Issues: Solving the World’s Open Source Software Security Problem](https://warontherocks.com/2022/05/dependency-issues-solving-the-worlds-open-source-software-security-problem/) offers a well meditated view on the problem space as well
* [The Digital Economy Runs on Open Source. Here&rsquo;s How to Protect It](https://hbr.org/2021/09/the-digital-economy-runs-on-open-source-heres-how-to-protect-it) (HBR)
* [Report: 95% of IT leaders say Log4shell was &#8216;major wake-up call&#8217; for cloud security](https://venturebeat.com/2022/04/29/report-95-of-it-leaders-say-log4shell-was-major-wake-up-call-for-cloud-security/)
* Presentation: [Securing the Open Source Software Supply Chain](https://github.com/di/talks/raw/master/2022/pycon_us_2022/talk.pdf) at PyConUS2022 by Dustin Ingram
* Watch: [The state of open source security in 2022](https://www.helpnetsecurity.com/2022/04/13/open-source-security-video/) with Kurt Seifried
* Podcast: [Kubernetes Podcast from Google: Episode 174 - in-toto, with Santiago Torres-Arias](https://kubernetespodcast.com/episode/174-in-toto/)
* [EO 14028 and Supply Chain Security](https://www.testifysec.com/blog/turtles-all-the-way-down/)
* [Reducing Open Source Risk Throughout the Development, Delivery and Deployment of SBOMs](https://icitech.org/wp-content/uploads/2022/05/SBOM_Whitepaper.pdf), a May 2022 paper illustrating at a high level the differences between SBOMs in publishing, distribution and delivery scenarios; see pages 6-9
* [Open Source Security Foundation (OpenSSF) Security Mobilization Plan](https://openssf.org/oss-security-mobilization-plan/)
* [Not Just Third Party Risk](https://www.kusari.dev/blog/not_just_tprm/)
* Read: [NIST Provides Solid Guidance on Software Supply Chain Security in DevSecOps](https://www.csoonline.com/article/655648/nist-provides-solid-guidance-on-software-supply-chain-security-in-devsecops.html) (CSO Online) - Overview of NIST SP 800-204D on integrating supply chain security into CI/CD pipelines with recommendations for secure builds, artifact management, and zero-trust principles
* Read: [How Golang Manages Its Security Supply Chain](https://thenewstack.io/how-golang-manages-its-security-supply-chain/) (The New Stack) - Overview of Go's supply chain security practices including checksums, CapsLock, OSS-Fuzz, SBOMs and vulnerability databases
* [Open Source Security: How Digital Infrastructure Is Built on a House of Cards](https://www.lawfareblog.com/open-source-security-how-digital-infrastructure-built-house-cards)
* Read: [Kink in the Chain: Eight Perspectives on Software Supply Chain Risk Management](https://www.atlanticcouncil.org/content-series/cybersecurity-policy-and-strategy/kink-in-the-chain-eight-perspectives-on-software-supply-chain-risk-management/) from the Atlantic Council, featuring policy and industry perspectives on threats, tools, and government initiatives
* Series: [Bootstrapping Trust Part 1](https://openziti.io/bootstrapping-trust-part-1-encryption-everywhere) covering encryption, certificates, chains and roots of trust
* Contact sign-up sheet required: [The Rise of Continuous Packaging](https://cloudsmith.com/developers/resources/the-rise-of-continuous-packaging/) by Cloudsmith and O'Reilly
* [Supply Chain Security for Cloud Native Java](https://speakerdeck.com/thomasvitale/supply-chain-security-for-cloud-native-java) (from [Thomas Vitale](https://twitter.com/vitalethomas/status/1565714896154755075))
* Podcast: [It Depends](https://open.spotify.com/episode/6l6yZUVrg058krMIrk8dTi?si=vZdjcI9mRRepHW-Q4B2r-w&nd=1) with Trail of Bits
* [New security concerns for the open-source software supply chain](https://www.helpnetsecurity.com/2022/10/17/security-concerns-open-source-software-supply-chain/) (top level findings from The State of the Software Supply Chain: Open Source Edition 2022)
* [Software Supply Chain Primer v0.93](https://docs.google.com/document/d/1Kq6e8DZ9G1MzKP3Tnlf6bXWLf41ad_tdTKs8ikfhGJ0/edit#heading=h.30j0zll) (June 2022)