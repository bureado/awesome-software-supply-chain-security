# awesome-software-supply-chain-security [![Awesome](https://awesome.re/badge.svg)](https://awesome.re)

A compilation of resources in the software supply chain security domain, with emphasis on open source.

## About the categories

There is no prescribed taxonomy for this domain. The [supply-chain-synthesis](https://github.com/AevaOnline/supply-chain-synthesis/) repo offers a long-form read on why that's the case, plus helpful pointers to understand and navigate it as it evolves.

For `awesome-software-supply-chain-security` we take the following high-level approach: different actors in the supply chain contribute **attestations** to the elements represented in the chain. In this process view, attestations are _emitted_, _augmented_ (e.g., during composition) and _verified_. Using this lens we can identify a large group of "subjects" (dependencies), distinct categories of "facts" (licenses or vulnerabilities) and the specific role of identity, provenance and build systems. This is the rationale behind the current headings, which are expected to evolve with the domain.

## Dependency management

This section includes: package management, library management, dependency management, vendored dependency management, by-hash searches, package, library and dependency naming, library behavior labeling, library publishing, registries and repositories, publishing gates and scans, dependency lifecycle.

### SBOM

This section includes: package/library scanners and detectors, SBOM formats, standards, authoring and validation, and a few applications.

### Vulnerability information exchange

## Point-of-use validations

This section includes: admission and ingestion policies, pull-time verification, 

## Identity and provenance

This section includes: 

## Frameworks and best practice references

This section includes: reference architectures and authoritative compilations of supply chain attacks and the emerging categories.

## Build techniques

This section includes: reproducible builds, hermetic builds, bootstrappable builds, special considerations for CI/CD systems, best practices building artifacts such as OCI containers, etc.

## Others in need of categorization

## Talks, articles, media coverage and other reading

