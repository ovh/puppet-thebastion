# @summary Default parameter values for thebastion module
#
class thebastion::params {
  # Install parameters
  $install_thebastion                       = true
  $install_packages                         = true
  $install_address                          = 'https://github.com/ovh/the-bastion'

  case $facts['os']['family'] {
    'Debian': {
      $_base_package_list = [
        'acl',
        'bash',
        'binutils',
        'coreutils',
        'cryptsetup',
        'curl',
        'expect',
        'fortunes-bofh-excuses',
        'fping',
        'gnupg',
        'inotify-tools',
        'iputils-ping',
        'libcgi-pm-perl',
        'libcommon-sense-perl',
        'libdatetime-perl',
        'libdbd-sqlite3-perl',
        'libdigest-sha-perl',
        'libgnupg-perl',
        'libjson-perl',
        'libjson-xs-perl',
        'liblinux-prctl-perl',
        'libnet-dns-perl',
        'libnet-ip-perl',
        'libnet-netmask-perl',
        'libnet-server-perl',
        'libnet-ssleay-perl',
        'libpam-google-authenticator',
        'libterm-readkey-perl',
        'libterm-readline-gnu-perl',
        'libtimedate-perl',
        'libwww-perl',
        'locales',
        'lsof',
        'mosh',
        'netcat',
        'openssh-server',
        'pamtester',
        'rsync',
        'sqlite3',
        'sudo',
        'xz-utils',
      ]
      if ($facts['os']['name'] == 'Ubuntu' and $facts['os']['release']['major'] in ['14.04', '16.04'])
      or ($facts['os']['name'] == 'Debian' and $facts['os']['release']['major'] == '8') {
        $_additional_packages_list = [
          'openssh-blacklist',
          'openssh-blacklist-extra',
        ]
      }
      else {
        $_additional_packages_list = [ ]
      }
    }
    'RedHat': {
      $_base_package_list = [
        'acl',
        'bash',
        'binutils',
        'cracklib-dicts',
        'cryptsetup',
        'curl',
        'expect',
        'fping',
        'gnupg',
        'google-authenticator',
        'inotify-tools',
        'lsof',
        'mosh',
        'nc',
        'openssh-server',
        'pamtester',
        'passwd',
        'perl-CGI',
        'perl-DateTime',
        'perl-DBD-SQLite',
        'perl-Digest',
        'perl-JSON',
        'perl-JSON-XS',
        'perl-libwww-perl',
        'perl-Net-DNS',
        'perl-Net-IP',
        'perl-Net-Netmask',
        'perl-Net-Server',
        'perl-Sys-Syslog',
        'perl-TermReadKey',
        'perl-Term-ReadLine-Gnu',
        'perl(Test::More)',
        'perl-TimeDate',
        'perl-Time-HiRes',
        'perl-Time-Piece',
        'qrencode-libs',
        'rsync',
        'sqlite',
        'sudo',
        'which',
        'xz',
      ]
      if ($facts['operatingsystemmajrelease'] == '7') {
        $_additional_packages_list = [
          'coreutils',
          'fortune-mod',
        ]
      }
      else {
        $_additional_packages_list = [ ]
      }
    }
    default : {
      $_base_package_list        = [ ]
      $_additional_packages_list = [ ]
    }
  }

  $package_list = concat($_base_package_list, $_additional_packages_list)

  # Main config parameters
  $account_create_default_personal_accesses = [ ]
  $account_create_supplementary_groups      = ['osh-accountListEgressKeys']
  $account_expired_message                  = 'Sorry, but your account has expired (#DAYS# days), access denied by policy. Ask an admin to unlock your account.'
  $account_external_validation_program      = '/bin/true'
  $account_ext_validation_deny_on_failure   = true
  $account_max_inactive_days                = 0
  $account_mfapolicy                        = 'enabled'
  $account_uid_max                          = 99999
  $account_uid_min                          = 2000
  $admin_accounts                           = [ ]
  $allowed_egress_ssh_algorithms            = ['rsa', 'ecdsa', 'ed25519']
  $allowed_ingress_ssh_algorithms           = ['rsa', 'ecdsa', 'ed25519']
  $allowed_networks                         = [ ]
  $always_active_accounts                   = [ ]
  $bastion_basedir                          = '/opt/bastion'
  $bastion_identifier                       = $::fqdn
  $bastion_listen_port                      = 22
  $bastion_name                             = 'bst'
  $debug                                    = false
  $default_account_egress_key_algorithm     = 'ed25519'
  $default_account_egress_key_size          = 256
  $default_login                            = ''
  $display_last_login                       = true
  $documentation_url                        = 'https://ovh.github.io/the-bastion/'
  $egress_keys_from                         = [ ]
  $enable_account_access_log                = true
  $enable_account_sql_log                   = true
  $enable_global_access_log                 = true
  $enable_global_sql_log                    = true
  $enable_syslog                            = true
  $forbidden_networks                       = [ ]
  $idle_kill_timeout                        = 0
  $idle_lock_timeout                        = 0
  $ingress_keys_from                        = [ ]
  $ingress_keys_from_allow_override         = false
  $ingress_to_egress_rules                  = [ ]
  $interactive_mode_allowed                 = true
  $interactive_mode_timeout                 = 60
  $keyboard_interactive_allowed             = false
  $maximum_ingress_rsa_key_size             = 8192
  $maximum_egress_rsa_key_size              = 8192
  $minimum_ingress_rsa_key_size             = 2048
  $minimum_egress_rsa_key_size              = 2048
  $mfa_password_inactive_days               = -1
  $mfa_password_max_days                    = 90
  $mfa_password_min_days                    = 0
  $mfa_password_warn_days                   = 15
  $mfa_post_command                         = [ ]
  $mosh_allowed                             = false
  $mosh_command_line                        = ''
  $mosh_timeout_network                     = 86400
  $mosh_timeout_signal                      = 30
  $password_allowed                         = false
  $read_only_slave_mode                     = false
  $remote_command_escape_by_default         = false
  $ssh_client_debug_level                   = 0
  $ssh_client_has_option_e                  = false
  $super_owner_accounts                     = [ ]
  $syslog_description                       = 'bastion'
  $syslog_facility                          = 'local7'
  $telnet_allowed                           = false
  $ttyrec_additional_parameters             = [ ]
  $ttyrec_filename_format                   = '%Y-%m-%d.%H-%M-%S.#usec#.&uniqid.ttyrec'
  $ttyrec_group_id_offset                   = 100000
  $warn_before_kill_seconds                 = 0
  $warn_before_lock_seconds                 = 0

  # Addons parameters
  $backup_acl_keys_days_to_keep             = 90
  $backup_acl_keys_destdir                  = '/root/backups'
  $backup_acl_keys_gpgkeys                  = undef
  $backup_acl_keys_logfacility              = undef
  $backup_acl_keys_logfile                  = undef
  $backup_acl_keys_push_remote              = ''
  $backup_acl_keys_push_options             = ''
  $encrypt_rsync_and_move_to_directory      = '/home/.encrypt'
  $encrypt_rsync_delay_before_remove_days   = 7
  $encrypt_rsync_destination                = ''
  $encrypt_rsync_logfile                    = undef
  $encrypt_rsync_move_delay_days            = 14
  $encrypt_rsync_recipients                 = [['']]
  $encrypt_rsync_rsh                        = ''
  $encrypt_rsync_signing_key                = undef
  $encrypt_rsync_signing_key_passphrase     = undef
  $encrypt_rsync_syslog_facility            = undef
  $http_proxy_ciphers                       = ''
  $http_proxy_enabled                       = false
  $http_proxy_insecure                      = false
  $http_proxy_min_servers                   = 8
  $http_proxy_min_spare_servers             = 8
  $http_proxy_max_servers                   = 32
  $http_proxy_max_spare_servers             = 16
  $http_proxy_port                          = 8443
  $http_proxy_ssl_certificate               = '/etc/ssl/certs/ssl-cert-snakeoil.pem'
  $http_proxy_ssl_key                       = '/etc/ssl/private/ssl-cert-snakeoil.key'
  $http_proxy_timeout                       = 120
  $piv_grace_reaper_syslog                  = undef
  $sync_watcher_enabled                     = false
  $sync_watcher_logdir                      = undef
  $sync_watcher_remote_host_list            = [ ]
  $sync_watcher_remote_user                 = ''
  $sync_watcher_rsh_cmd                     = ''
  $sync_watcher_syslog                      = ''
  $sync_watcher_timeout                     = 120
}
