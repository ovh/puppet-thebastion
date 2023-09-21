# @summary
#   Builds a bastion's plugin configuration
# @param configuration
#   Configuration to pass as a json
#   disabled key value must be boolean
#   mfa_required key value must be in password totp any none
define thebastion::plugin (
  Hash $configuration = {}
) {
  # This check exists because of /etc/bastion directory creation
  if ! defined(Class['thebastion']) {
    fail('You must include the thebastion base class before using plugin defined resource')
  }

  $plugin_config_file = "/etc/bastion/plugin.${title}.conf"

  if has_key($configuration, 'disabled') {
    assert_type(Boolean, $configuration['disabled']) |$expected, $actual| {
      fail("disabled configuration in a plugin must be Boolean. Expected ${expected} got ${actual}")
    }
  }

  if has_key($configuration, 'mfa_required') {
    assert_type(Enum['password','totp','any','none'], $configuration['mfa_required']) |$expected, $actual| {
      fail("mfa_required configuration in a plugin must have value in password totp any none. Expected ${expected} got ${actual}")
    }
  }

  concat { $plugin_config_file:
    ensure => present,
    owner  => 'root',
    group  => 'root',
    mode   => '0644',
  }

  concat::fragment { "thebastion-plugin-${title}-header":
    target  => $plugin_config_file,
    content => epp('thebastion/plugin_conf_header.epp'),
    order   => '001',
  }

  concat::fragment { "thebastion-plugin-${title}-conf":
    target  => $plugin_config_file,
    content => to_json_pretty($configuration, true),
    order   => '100',
  }
}
