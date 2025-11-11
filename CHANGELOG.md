# Changelog

## [0.10.0](https://github.com/scop/hashpipe/compare/0.9.2...v0.10.0) (2025-11-11)


### Features

* **argcomplete:** register key, prefix, and regex non-completions ([5accf80](https://github.com/scop/hashpipe/commit/5accf807f366e63aebf649748f14067421ada55a))
* completion improvements ([8b6f42a](https://github.com/scop/hashpipe/commit/8b6f42a87afa9ddc41d8bb0796550621d1c1e15b))


### Bug Fixes

* don't overload internal digest module variable with different types ([20b257b](https://github.com/scop/hashpipe/commit/20b257b858eea040d28c95c8c097921952e638ed))
* **mypy:** import skipping config with pytest 7 ([712843a](https://github.com/scop/hashpipe/commit/712843a6b1b35d0385a9c0e5b603502a4a961af4))
* **pytype:** don't try to run for Python &lt; 3.6 ([d34d722](https://github.com/scop/hashpipe/commit/d34d722dc14da1813acda0bf058c279b4612e93f))
* **renovate:** config syntax ([b0a1130](https://github.com/scop/hashpipe/commit/b0a1130fe5d186742ad8923597a3d2836c489658))
* **renovate:** config syntax ([c43c0ce](https://github.com/scop/hashpipe/commit/c43c0cede0d219ca26898396f9c556c6bfb10204))

### 0.9.2 (2020-01-12)

### Features

* `-A`/`--available-algorithms` option for listing available algorithms
* optional shell completion support using argcomplete
