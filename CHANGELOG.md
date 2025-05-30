# Changelog

## 0.1.0 (2025-05-30)


### Bug Fixes

* do not ship BUILD file to let consumer generate it via Gazelle ([#1](https://github.com/albertocavalcante/netrcgo/issues/1)) ([39a86c2](https://github.com/albertocavalcante/netrcgo/commit/39a86c2681b98f5466b4fee79cd5280204a111a4))
* remove module.bazel ([#2](https://github.com/albertocavalcante/netrcgo/issues/2)) ([7cdca39](https://github.com/albertocavalcante/netrcgo/commit/7cdca393dc177b6075536b50dd2d5cf15183a784))

## [Unreleased]

### Features

- Initial implementation of netrc file parsing
- Support for machine and default entries  
- File permission validation
- Cross-platform support for finding .netrc files
- Comprehensive test coverage

### Security

- File permission validation on Unix-like systems
- Secure error handling that doesn't leak credentials
