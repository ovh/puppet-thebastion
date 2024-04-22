# @summary main thebastion configuration
#
#class thebastion::config inherits thebastion {
class thebastion::config {
  assert_private()

  $main_config_file = '/etc/bastion/bastion.conf'

  # First build configuration hash with given parameters as well as tweaks for user niceness
  $conf = {
    'accountCreateDefaultPersonalAccesses'   => $thebastion::account_create_default_personal_accesses,
    'accountCreateSupplementaryGroups'       => $thebastion::account_create_supplementary_groups,
    'accountExpiredMessage'                  => $thebastion::account_expired_message,
    'accountExternalValidationProgram'       => $thebastion::account_external_validation_program,
    'accountExternalValidationDenyOnFailure' => $thebastion::account_ext_validation_deny_on_failure,
    'accountMaxInactiveDays'                 => $thebastion::account_max_inactive_days,
    'accountMFAPolicy'                       => $thebastion::account_mfapolicy,
    'accountUidMax'                          => $thebastion::account_uid_max,
    'accountUidMin'                          => $thebastion::account_uid_min,
    'adminAccounts'                          => $thebastion::admin_accounts,
    'allowedEgressSshAlgorithms'             => $thebastion::allowed_egress_ssh_algorithms,
    'allowedIngressSshAlgorithms'            => $thebastion::allowed_ingress_ssh_algorithms,
    'allowedNetworks'                        => $thebastion::allowed_networks,
    'alwaysActiveAccounts'                   => $thebastion::always_active_accounts,
    'bastionCommand'                         => "ssh ACCOUNT@${thebastion::bastion_identifier} -p ${thebastion::bastion_listen_port} -t -- ",
    'bastionName'                            => $thebastion::bastion_name,
    'debug'                                  => $thebastion::debug,
    'defaultAccountEgressKeyAlgorithm'       => $thebastion::default_account_egress_key_algorithm,
    'defaultAccountEgressKeySize'            => $thebastion::default_account_egress_key_size,
    'defaultLogin'                           => $thebastion::default_login,
    'displayLastLogin'                       => $thebastion::display_last_login,
    'dnsSupportLevel'                        => $thebastion::dns_support_level,
    'documentationURL'                       => $thebastion::documentation_url,
    'egressKeysFrom'                         => $thebastion::egress_keys_from,
    'enableAccountAccessLog'                 => $thebastion::enable_account_access_log,
    'enableAccountSqlLog'                    => $thebastion::enable_account_sql_log,
    'enableGlobalAccessLog'                  => $thebastion::enable_global_access_log,
    'enableGlobalSqlLog'                     => $thebastion::enable_global_sql_log,
    'enableSyslog'                           => $thebastion::enable_syslog,
    'forbiddenNetworks'                      => $thebastion::forbidden_networks,
    'idleKillTimeout'                        => $thebastion::idle_kill_timeout,
    'idleLockTimeout'                        => $thebastion::idle_lock_timeout,
    'ingressKeysFrom'                        => $thebastion::ingress_keys_from,
    'ingressKeysFromAllowOverride'           => $thebastion::ingress_keys_from_allow_override,
    'ingressToEgressRules'                   => $thebastion::ingress_to_egress_rules,
    'interactiveModeAllowed'                 => $thebastion::interactive_mode_allowed,
    'interactiveModeTimeout'                 => $thebastion::interactive_mode_timeout,
    'keyboardInteractiveAllowed'             => $thebastion::keyboard_interactive_allowed,
    'maximumIngressRsaKeySize'               => $thebastion::maximum_ingress_rsa_key_size,
    'maximumEgressRsaKeySize'                => $thebastion::maximum_egress_rsa_key_size,
    'minimumIngressRsaKeySize'               => $thebastion::minimum_ingress_rsa_key_size,
    'minimumEgressRsaKeySize'                => $thebastion::minimum_egress_rsa_key_size,
    'MFAPasswordInactiveDays'                => $thebastion::mfa_password_inactive_days,
    'MFAPasswordMaxDays'                     => $thebastion::mfa_password_max_days,
    'MFAPasswordMinDays'                     => $thebastion::mfa_password_min_days,
    'MFAPasswordWarnDays'                    => $thebastion::mfa_password_warn_days,
    'MFAPostCommand'                         => $thebastion::mfa_post_command,
    'moshAllowed'                            => $thebastion::mosh_allowed,
    'moshCommandLine'                        => $thebastion::mosh_command_line,
    'moshTimeoutNetwork'                     => $thebastion::mosh_timeout_network,
    'moshTimeoutSignal'                      => $thebastion::mosh_timeout_signal,
    'passwordAllowed'                        => $thebastion::password_allowed,
    'readOnlySlaveMode'                      => $thebastion::read_only_slave_mode,
    'sshClientDebugLevel'                    => $thebastion::ssh_client_debug_level,
    'sshClientHasOptionE'                    => $thebastion::ssh_client_has_option_e,
    'superOwnerAccounts'                     => $thebastion::super_owner_accounts,
    'syslogDescription'                      => $thebastion::syslog_description,
    'syslogFacility'                         => $thebastion::syslog_facility,
    'remoteCommandEscapeByDefault'           => $thebastion::remote_command_escape_by_default,
    'telnetAllowed'                          => $thebastion::telnet_allowed,
    'ttyrecAdditionalParameters'             => $thebastion::ttyrec_additional_parameters,
    'ttyrecFilenameFormat'                   => $thebastion::ttyrec_filename_format,
    'ttyrecGroupIdOffset'                    => $thebastion::ttyrec_group_id_offset,
    'ttyrecStealthStdoutPattern'             => $thebastion::ttyrec_stealth_stdout_pattern,
    'warnBeforeKillSeconds'                  => $thebastion::warn_before_kill_seconds,
    'warnBeforeLockSeconds'                  => $thebastion::warn_before_lock_seconds,
  }

  # Uid check
  if ($thebastion::account_uid_max <= $thebastion::account_uid_min) {
    fail('account_uid_max must be strictly superior than account_uid_min')
  }

  # Ttyrec Group ID Offsets check
  if ($thebastion::ttyrec_group_id_offset <= $thebastion::account_uid_max) {
    fail('ttyrec_group_id_offset must be strictly superior than account_uid_max')
  }

  # Rsa key size check
  if ($thebastion::maximum_ingress_rsa_key_size < $thebastion::minimum_ingress_rsa_key_size) {
    fail('maximum_ingress_rsa_key_size must be superior than minimum_ingress_rsa_key_size')
  }

  if ($thebastion::maximum_egress_rsa_key_size < $thebastion::minimum_egress_rsa_key_size) {
    fail('maximum_egress_rsa_key_size must be superior than minimum_egress_rsa_key_size')
  }

  # Egress algorithms and associated size consistency checks
  case $thebastion::default_account_egress_key_algorithm {
    'rsa' : {
      if ($thebastion::default_account_egress_key_size < 2048) or ($thebastion::default_account_egress_key_size > 8192) {
        fail('When default_account_egress_key_algorithm is set to rsa, default_account_egress_key_size must be between 2048 and 8192')
      }
    }
    'ecdsa' : {
      if ! ($thebastion::default_account_egress_key_size in [256,384,521]) {
        fail('When default_account_egress_key_algorithm is set to ecdsa, default_account_egress_key_size must be 256, 384 or 521')
      }
    }
    'ed25519' : {
      if ($thebastion::default_account_egress_key_size != 256) {
        fail('When default_account_egress_key_algorithm is set to ed25519, default_account_egress_key_size must be 256')
      }
    }
    default : { fail('default_account_egress_key_algorithm should be set to rsa, ecdsa or ed25519') }
  }

  if ($thebastion::idle_kill_timeout <= $thebastion::idle_lock_timeout) and ($thebastion::idle_lock_timeout != 0) and ($thebastion::idle_kill_timeout != 0) {
    fail('When set to non-zero integers, idle_kill_timeout must be strictly higher than idle_lock_timeout')
  }

  # Ingress to Egress sanitize checks
  $thebastion::ingress_to_egress_rules.each |Array $rule| {
    # First check that the Array contains 3 items (not re-specifying type, will be done on the following
    assert_type(Array[Any, 3, 3], $rule) |$expected, $actual| {
      fail("Each rule inside ingress_to_egress_rules must be a 3-elements array, Expected ${expected} got ${actual}")
    }
    assert_type(Array[Stdlib::IP::Address::V4], $rule[0]) |$expected, $actual| {
      fail("First item of each rule inside ingress_to_egress_rules must be an array of IPv4 elements. Expected ${expected} got ${actual}")
    }
    assert_type(Array[Stdlib::IP::Address::V4], $rule[1]) |$expected, $actual| {
      fail("Second item of each rule inside ingress_to_egress_rules must be an array of IPv4 elements. Expected ${expected} got ${actual}")
    }
    assert_type(Enum['DENY', 'ALLOW', 'ALLOW-EXCLUSIVE'], $rule[2]) |$expected, $actual| {
      fail("Third item of each rule inside ingress_to_egress_rules must have value in DENY, ALLOW, ALLOW-EXCLUSIVE. Expected ${expected} got ${actual}")
    }
  }

  $thebastion::admin_accounts.each |String $user| {
    # We want to add the osh-admin group to an existing account on the system we apply the manifest to
    exec { "add_${user}_in_osh-admin_group":
      command => "getent passwd ${user} >/dev/null && usermod -a -G osh-admin ${user}",
      unless  => "id -nG ${user} | grep -q 'osh-admin'",
      path    => ['/usr/bin', '/bin', '/usr/sbin'],
      returns => [0, 2],
    }
  }

  file { '/etc/bastion':
    ensure => directory,
    owner  => 'root',
    group  => 'root',
    mode   => '0751',
  }

  concat { $main_config_file:
    ensure => present,
    owner  => 'root',
    group  => 'root',
    mode   => '0644',
  }

  # Main configuration file build

  concat::fragment { 'thebastion-header':
    target  => $main_config_file,
    content => epp('thebastion/bastion_conf_header.epp'),
    order   => '001',
  }

  concat::fragment { 'thebastion-conf':
    target  => $main_config_file,
    content => to_json_pretty($conf, true),
    order   => '100',
  }

  concat::fragment { 'thebastion-footer':
    target  => $main_config_file,
    content => epp('thebastion/bastion_conf_footer.epp'),
    order   => '800',
  }
}
