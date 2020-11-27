Puppet-Thebastion
=================

Puppet module for Thebastion management.

## Table of Contents

1. [Description](#description)
2. [Getting started](#setup)
    * [Setup requirements](#setup-requirements)
    * [Install and configure thebastion](#install-and-configure-thebastion)
3. [Usage - Configuration options and additional functionality](#usage)
4. [Limitations - OS compatibility](#limitations)

## Description

This module manages:
* Software installation (with the use of git and github).
* Dependencies on supported OS (packages).
* Main configuration
* Addons configuration
* Plugins configuration

## Setup

### Setup Requirements

This module has two dependencies:
* [Concat](https://forge.puppet.com/modules/puppetlabs/concat)
* [Stdlib](https://forge.puppet.com/modules/puppetlabs/stdlib)

### Install and configure thebastion

Simply call the main class in a Puppet manifest:

```puppet
class{'thebastion': }
```

## Usage

### Customize Installation

To ease integration to more complex setups, you can decide whether you want to
pull the code and/or install required system packages.

For instance, you can decide not to install dependencies packages with this
module. Simply pass the relevant parameter to the class:

```puppet
class {'thebastion':
  install_packages => false,
}
```

### Customize configuration and addons

This module allows every parameter to be customized via hiera, or via class
instantiation.

You can, for instance, change interactive mode timeout to 30 seconds:

```puppet
class {'thebastion':
  interactive_mode_timeout => 30,
}
```

You can consult [REFERENCES.md](REFERENCES.md) file for a complete list of
available parameters.

### Customize plugins configuration

For security reasons, or simple customization of a plugin, you might want to
change a plugin configuration.
You have multiple choices in order to do this:

* Instantiate a plugin configuration directly in your manifest:

```puppet
thebastion::plugin {'selfResetIngressKeys':
  configuration => {
    disabled => true,
  }
}
```

* Pass a list of plugins inside the main class:

```puppet
class {'thebastion':
  plugins => {
    selfResetIngressKeys => {
      configuration => {
        disabled => true,
      }
    }
  }
}
```

* Pass the same parameters via a hiera file:

```yaml
thebastion::plugins:
  selfResetIngressKeys:
    configuration:
      disabled: true
```

## Limitations

Take a close look at the supported distributions in [metadata.json](metadata.json) file.
Although the main configuration offers sane default values in order to be
directly operable, the addons configuration will require some tweaks in order
to be fully operational (e.g `sync_watcher_remote_host_list` parameter).

## Related

- [The Bastion](https://github.com/ovh/the-bastion) - The Bastion main repository

## License

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
