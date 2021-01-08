# Changelog

All notable changes to this project will be documented in this file.

## [v1.0.8](https://github.com/ovh/puppet-thebastion/tree/v1.0.8) (2021-01-08)

- fix: add exec return code 2 acceptable, avoids unnecessary fails if admin user doesn't exist yet 

## [v1.0.7](https://github.com/ovh/puppet-thebastion/tree/v1.0.7) (2021-01-07)

- [install] add install_address parameter to clone from wherever you want

## [v1.0.6](https://github.com/ovh/puppet-thebastion/tree/v1.0.6) (2021-01-06)

- [documentation] Fix documenation link to github

## [v1.0.5](https://github.com/ovh/puppet-thebastion/tree/v1.0.5) (2020-12-10)

- [plugins] sync_watcher : fix type as :port format is supported

## [v1.0.4](https://github.com/ovh/puppet-thebastion/tree/v1.0.4) (2020-12-07)

- [plugins] Remove useless comment inside epp

## [v1.0.3](https://github.com/ovh/puppet-thebastion/tree/v1.0.3) (2020-12-04)

- fix: skip undef values when outputing pretty JSON

## [v1.0.2](https://github.com/ovh/puppet-thebastion/tree/v1.0.2) (2020-12-03)

- Add puppet forge publish automation
- Add changelog file
- Fix module name in metadata.json file

## [v1.0.1](https://github.com/ovh/puppet-thebastion/tree/v1.0.1) (2020-11-30)

- fix: rename REFERENCES to REFERENCE to match puppet forge conventions
- fix: invert logic of osh-admin group inclusion, add /usr/sbin to path

## [v1.0.0](https://github.com/ovh/puppet-thebastion/tree/v1.0.0) (2020-11-27)

- Initial Release
