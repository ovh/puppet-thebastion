# @summary
#   Module to manage thebastion
#
# Bastion's install
#
# @param install_thebastion
#   Whether to install bastion's software
# @param install_packages
#   Whether to install package dependencies
# @param install_address
#   Address where to find source code of the bastion
#
# Bastion's main configuration
#
# @param account_create_default_personal_accesses
#   List of accesses to add to the personal access list of newly created accounts.
# @param account_create_supplementary_groups
#   List of groups to add a new account to
# @param account_expired_message
#   Customizes the message that will be printed to a user attempting to connect with an expired account
# @param account_external_validation_program
#   Script that will be called by the bastion, with the account name in parameter, to check whether this account should be allowed to connect to the bastion
# @param account_ext_validation_deny_on_failure
#   If we can't validate an account using the above configured program, this configuration option indicates whether we should deny or allow access.
# @param account_max_inactive_days
#   Deny access to accounts that didn't log in since at least that many days. A value of 0 means that this functionality is disabled
# @param account_mfapolicy
#    Set a MFA policy for the bastion accounts.
# @param account_uid_max
#   Maximum allowed UID for accounts on the bastion
# @param account_uid_min
#   Minimum allowed UID for accounts on the bastion
# @param admin_accounts
#   accounts that are Admins of the bastion
# @param allowed_egress_ssh_algorithms
#   the algorithms authorized for egress ssh public keys generated on the bastion
# @param allowed_ingress_ssh_algorithms
#   the algorithms authorized for ingress ssh public keys added to the bastion
# @param allowed_networks
#   Restricts egress connection attempts to those listed networks only
# @param always_active_accounts
#   List of accounts which should NOT be checked against the accountExternalValidationProgram mechanism
# @param bastion_basedir
#   Bastion basedir, where the bastion's code will be hosted
# @param bastion_identifier
#   Bastion identifier, to help build the bastion command parameter. Defaults to fqdn fact of the machine
# @param bastion_listen_port
#   Port used to connect to the bastion. Must be linked to an ssh instance which listens to it
# @param bastion_name
#   Name advertised in the aliases admins will give to bastion users
# @param debug
#   Enables or disables debug globally
# @param default_account_egress_key_algorithm
#   The default algorithm to use to create the egress key of a newly created account
# @param default_account_egress_key_size
#   The default size to use to create the egress key of a newly created account
# @param default_login
#   The default remote user to use for egress ssh connections where no user has been specified by bastion's caller
# @param display_last_login
#   Whether to display last login information on connection
# @param dns_support_level
#   Manage DNS Level resolution, 0 being no resolution, 1 forced resolution, 2 full resolution
# @param documentation_url
#   The URL of the documentation where users will be pointed to, for example when displaying help
# @param egress_keys_from
#   The IPs which will be added to the from="..." of the personal account keys and the group keys
# @param enable_account_access_log
#   Whether to log all accesses in the user's home /home/USER/USER-log-YYYYMM.log
# @param enable_account_sql_log
#   Whether to log all accesses (in a detailed SQL format) in the user's home /home/USER/USER-log-YYYYMM.sqlite
# @param enable_global_access_log
#   Whether to log all accesses in the old /home/osh.log (never rotated, world-writable -> discouraged)
# @param enable_global_sql_log
#   Whether to log all accesses (in a short SQL format) in /home/logkeeper/*.sqlite
# @param enable_syslog
#   Whether to send logs through syslog
# @param forbidden_networks
#   Prevents egress connection to the listed networks, even if they match configured allowed networks
# @param idle_lock_timeout
#   The number of seconds of input idle time after which the session is locked. 0 means disabled
# @param idle_kill_timeout
#   The number of seconds of input idle time after which the session is killed. 0 means disabled
# @param ingress_keys_from
#   IPs used to build the from="" in front of the ingress account public keys used to connect to the bastion
# @param ingress_keys_from_allow_override
#   Whether to ignore the IP passed and replaced by the IPs in the ingressKeysFrom configuration option
# @param ingress_to_egress_rules
#   Fine-grained rules (netfilter like) to apply global restrictions to possible egress destinations given ingress IPs.
# @param interactive_mode_allowed
#   Whether to activate interactive mode
# @param interactive_mode_timeout
#   Idle seconds after which the user is disconnected from the bastion when in interactive mode
# @param keyboard_interactive_allowed
#   Whether to allow keyboard-interactive authentication when publickey auth is requested for egress connections, this is needed e.g. for 2FA
# @param maximum_ingress_rsa_key_size
#   The maximum allowed size for ingress RSA keys (user->bastion)
# @param maximum_egress_rsa_key_size
#   The maximum allowed size for ingress RSA keys (bastion->server)
# @param minimum_ingress_rsa_key_size
#   The minimum allowed size for ingress RSA keys (user->bastion)
# @param minimum_egress_rsa_key_size
#   The minimum allowed size for egress RSA keys (bastion->server)
# @param mfa_password_inactive_days
#   For the PAM UNIX password MFA, the account will be blocked after the password is expired (and not renewed) for this amount of days
# @param mfa_password_max_days
#   For the PAM UNIX password MFA, sets the maximum amount of days after which the password must be changed
# @param mfa_password_min_days
#   For the PAM UNIX password MFA, sets the minimum amount of days between two password changes
# @param mfa_password_warn_days
#   For the PAM UNIX password MFA, sets the number of days before expiration on which the user will be warned to change his password
# @param mfa_post_command
#   When using JIT MFA (i.e. not directly by calling PAM from SSHD's configuration, but using pamtester from within the code), exec this command on success
# @param mosh_allowed
#   Whether mosh is allowed on the bastion
# @param mosh_command_line
#   Additional parameters that will be passed as-is to mosh-server
# @param mosh_timeout_network
#   Number of seconds of inactivity (network-wise) after a mosh-server will exit
# @param mosh_timeout_signal
#   Number of seconds of inactivity (network-wise) a mosh-server will wait after receiving a SIGUSR1 before exiting
# @param password_allowed
#   Whether to password authentication for egress ssh
# @param plugins
#   A hash of plugins definitions to instantiate for the bastion
# @param read_only_slave_mode
#   Whether the instance of the bastion is slave or not
# @param remote_command_escape_by_default
#   Whether to escape simple quotes in remote commands by default
# @param ssh_client_debug_level
#   The number of -v that will be added to the ssh client command line when starting a session
# @param ssh_client_has_option_e
#   Set to 1 if your ssh client supports the -E option and you want to use it to log debug info on opened sessions
# @param super_owner_accounts
#   List of accounts that are considered as super group owners
# @param syslog_description
#   Sets the description that will be used for syslog
# @param syslog_facility
#   Sets the facility that will be used for syslog
# @param telnet_allowed
#   Whether to allow telnet egress connections
# @param ttyrec_additional_parameters
#   Additional parameters you want to pass to ttyrec invocation
# @param ttyrec_filename_format
#   Sets the filename format of the output files of ttyrec for a given session
# @param ttyrec_group_id_offset
#   Offset to apply on user group uid to create -tty group
# @param ttyrec_stealth_stdout_pattern
#   Regex which will be matched against a potential remote command specified when connecting through SSH to a remote server. If the regex matches, then we'll instruct ttyrec to NOT record stdout for this session.
# @param warn_before_kill_seconds
#   Seconds before idleKillTimeout where the user will receive a warning message about the upcoming kill of his session
# @param warn_before_lock_seconds
#   Seconds before idleLockTimeout where the user will receive a warning message about the upcoming lock of his session
#
# Bastion's addons configuration
#
# @param backup_acl_keys_destdir
#   Directory where to put the .tar.gz files
# @param backup_acl_keys_days_to_keep
#   Number of days to keep backups locally
# @param backup_acl_keys_logfacility
#   Will use syslog with the following facility to log, won't use syslog otherwise
# @param backup_acl_keys_logfile
#   File where to put script logs, if not defined, will not log into a file
# @param backup_acl_keys_gpgkeys
#   List of gpg keys to encrypt to
# @param backup_acl_keys_push_options
#   Additional options to pass to scp
# @param backup_acl_keys_push_remote
#   Scp remote host push backups to
# @param encrypt_rsync_and_move_to_directory
#   After encryption (and compression), move ttyrec files to subdirs of this directory
# @param encrypt_rsync_delay_before_remove_days
#   After encryption/compression, and successful rsync to remote, wait for this amount of days before removing the files locally
# @param encrypt_rsync_move_delay_days
#   Don't touch ttyrec files that have a modification time more recent than this
# @param encrypt_rsync_destination
#   String passed to rsync as a destination. If empty, will DISABLE rsync
# @param encrypt_rsync_logfile
#   File where the logs will be written to
# @param encrypt_rsync_recipients
#   Ttyrecs will be encrypted with those GPG keys, possibly using multi-layer GPG encryption
# @param encrypt_rsync_rsh
#   Useful to specify an SSH key or an alternate SSH port for example
# @param encrypt_rsync_signing_key
#   ID of the key used to sign the ttyrec files (must be in the local keyring)
# @param encrypt_rsync_signing_key_passphrase
#   Will be used by the script to unlock the key and sign with it
# @param encrypt_rsync_syslog_facility
#   Syslog facility to log to if defined
# @param http_proxy_ciphers
#   Ordered list the TLS server ciphers, in openssl classic format.
# @param http_proxy_enabled
#   Whether to enable the http proxy daemon
# @param http_proxy_insecure
#   Whether to ignore SSL certificate verification for the connection between the bastion and the devices
# @param http_proxy_min_servers
#   Number of child processes to start at launch
# @param http_proxy_min_spare_servers
#   The daemon will ensure that there is at least this number of children idle & ready to accept new connections
# @param http_proxy_max_servers
#   Hard maximum number of child processes that can be active at any given time no matter what
# @param http_proxy_max_spare_servers
#   The daemon will kill *idle* children to keep their number below this maximum when traffic is low
# @param http_proxy_port
#   Port to listen to
# @param http_proxy_ssl_certificate
#   File that contains the server SSL certificate in PEM format
# @param http_proxy_ssl_key
#   File that contains the server SSL key in PEM format
# @param http_proxy_timeout
#   Timeout delay (in seconds) for the connection between the bastion and the devices
# @param http_proxy_allowed_egress_protocols
#   List of the allowed protocols to be used on the egress side of the HTTPS proxy, supported protocols: https, http
# @param piv_grace_reaper_syslog
#   Syslog facility to log to if defined
# @param sync_watcher_enabled
#   Whether to enable the script
# @param sync_watcher_logdir
#   Directory where to log output from the script, if defined
# @param sync_watcher_remote_host_list
#   Remote hosts to connect to while rsyncing
# @param sync_watcher_remote_user
#   Remote user to connect as while rsyncing
# @param sync_watcher_rsh_cmd
#   This will be passed as the --rsh parameter of rsync
# @param sync_watcher_syslog
#   Syslog facility to use, if defined
# @param sync_watcher_timeout
#   This will be the maximum delay, in seconds, after which rsync will be launched even if no change was detected
class thebastion (
  # Install parameters
  Boolean $install_thebastion                                                       = $thebastion::params::install_thebastion,
  Boolean $install_packages                                                         = $thebastion::params::install_packages,
  String  $install_address                                                          = $thebastion::params::install_address,

  # Configuration parameters
  Array   $account_create_default_personal_accesses                                 = $thebastion::params::account_create_default_personal_accesses,
  Array   $account_create_supplementary_groups                                      = $thebastion::params::account_create_supplementary_groups,
  String  $account_expired_message                                                  = $thebastion::params::account_expired_message,
  String  $account_external_validation_program                                      = $thebastion::params::account_external_validation_program,
  Boolean $account_ext_validation_deny_on_failure                                   = $thebastion::params::account_ext_validation_deny_on_failure,
  Integer[0,default] $account_max_inactive_days                                     = $thebastion::params::account_max_inactive_days,
  Enum['enabled','disabled','totp-required',
  'password-required', 'any-required'] $account_mfapolicy                           = $thebastion::params::account_mfapolicy,
  Integer[1001,default] $account_uid_max                                            = $thebastion::params::account_uid_max,
  Integer[1000,default] $account_uid_min                                            = $thebastion::params::account_uid_min,
  Array $admin_accounts                                                             = $thebastion::params::admin_accounts,
  Array[Enum['dsa', 'rsa', 'ecdsa', 'ed25519']] $allowed_egress_ssh_algorithms      = $thebastion::params::allowed_egress_ssh_algorithms,
  Array[Enum['dsa', 'rsa', 'ecdsa', 'ed25519']] $allowed_ingress_ssh_algorithms     = $thebastion::params::allowed_ingress_ssh_algorithms,
  Array[Stdlib::IP::Address::V4] $allowed_networks                                  = $thebastion::params::allowed_networks,
  Array $always_active_accounts                                                     = $thebastion::params::always_active_accounts,
  Stdlib::AbsolutePath $bastion_basedir                                             = $thebastion::params::bastion_basedir,
  Variant[Stdlib::Fqdn,Stdlib::IP::Address::V4::Nosubnet] $bastion_identifier       = $thebastion::params::bastion_identifier,
  Integer[1,65535] $bastion_listen_port                                             = $thebastion::params::bastion_listen_port,
  String $bastion_name                                                              = $thebastion::params::bastion_name,
  Boolean $debug                                                                    = $thebastion::params::debug,
  Enum['rsa', 'ecdsa', 'ed25519'] $default_account_egress_key_algorithm             = $thebastion::params::default_account_egress_key_algorithm,
  Integer[256,8192] $default_account_egress_key_size                                = $thebastion::params::default_account_egress_key_size,
  String $default_login                                                             = $thebastion::params::default_login,
  Boolean $display_last_login                                                       = $thebastion::params::display_last_login,
  Integer[0,2] $dns_support_level                                                   = $thebastion::params::dns_support_level,
  Stdlib::HTTPUrl $documentation_url                                                = $thebastion::params::documentation_url,
  Array[Stdlib::IP::Address::V4] $egress_keys_from                                  = $thebastion::params::egress_keys_from,
  Boolean $enable_account_access_log                                                = $thebastion::params::enable_account_access_log,
  Boolean $enable_account_sql_log                                                   = $thebastion::params::enable_account_sql_log,
  Boolean $enable_global_access_log                                                 = $thebastion::params::enable_global_access_log,
  Boolean $enable_global_sql_log                                                    = $thebastion::params::enable_global_sql_log,
  Boolean $enable_syslog                                                            = $thebastion::params::enable_syslog,
  Array[Stdlib::IP::Address::V4] $forbidden_networks                                = $thebastion::params::forbidden_networks,
  Integer[0,default] $idle_kill_timeout                                             = $thebastion::params::idle_kill_timeout,
  Integer[0,default] $idle_lock_timeout                                             = $thebastion::params::idle_lock_timeout,
  Array[Stdlib::IP::Address::V4] $ingress_keys_from                                 = $thebastion::params::ingress_keys_from,
  Boolean $ingress_keys_from_allow_override                                         = $thebastion::params::ingress_keys_from_allow_override,
  Array $ingress_to_egress_rules                                                    = $thebastion::params::ingress_to_egress_rules,
  Boolean $interactive_mode_allowed                                                 = $thebastion::params::interactive_mode_allowed,
  Integer[0,default] $interactive_mode_timeout                                      = $thebastion::params::interactive_mode_timeout,
  Boolean $keyboard_interactive_allowed                                             = $thebastion::params::keyboard_interactive_allowed,
  Integer[0,default] $maximum_ingress_rsa_key_size                                  = $thebastion::params::maximum_ingress_rsa_key_size,
  Integer[0,default] $maximum_egress_rsa_key_size                                   = $thebastion::params::maximum_egress_rsa_key_size,
  Integer[0,default] $minimum_ingress_rsa_key_size                                  = $thebastion::params::minimum_ingress_rsa_key_size,
  Integer[0,default] $minimum_egress_rsa_key_size                                   = $thebastion::params::minimum_egress_rsa_key_size,
  Integer[-1,default] $mfa_password_inactive_days                                   = $thebastion::params::mfa_password_inactive_days,
  Integer[0,default] $mfa_password_max_days                                         = $thebastion::params::mfa_password_max_days,
  Integer[0,default] $mfa_password_min_days                                         = $thebastion::params::mfa_password_min_days,
  Integer[0,default] $mfa_password_warn_days                                        = $thebastion::params::mfa_password_warn_days,
  Array $mfa_post_command                                                           = $thebastion::params::mfa_post_command,
  Boolean $mosh_allowed                                                             = $thebastion::params::mosh_allowed,
  String  $mosh_command_line                                                        = $thebastion::params::mosh_command_line,
  Integer[1,default] $mosh_timeout_network                                          = $thebastion::params::mosh_timeout_network,
  Integer[1,default] $mosh_timeout_signal                                           = $thebastion::params::mosh_timeout_signal,
  Boolean $password_allowed                                                         = $thebastion::params::password_allowed,
  Hash $plugins                                                                     = {},
  Boolean $read_only_slave_mode                                                     = $thebastion::params::read_only_slave_mode,
  Boolean $remote_command_escape_by_default                                         = $thebastion::params::remote_command_escape_by_default,
  Integer[0,3] $ssh_client_debug_level                                              = $thebastion::params::ssh_client_debug_level,
  Boolean $ssh_client_has_option_e                                                  = $thebastion::params::ssh_client_has_option_e,
  Array $super_owner_accounts                                                       = $thebastion::params::super_owner_accounts,
  String $syslog_description                                                        = $thebastion::params::syslog_description,
  String $syslog_facility                                                           = $thebastion::params::syslog_facility,
  Boolean $telnet_allowed                                                           = $thebastion::params::telnet_allowed,
  Array $ttyrec_additional_parameters                                               = $thebastion::params::ttyrec_additional_parameters,
  String $ttyrec_filename_format                                                    = $thebastion::params::ttyrec_filename_format,
  Integer[1002,default] $ttyrec_group_id_offset                                     = $thebastion::params::ttyrec_group_id_offset,
  Optional[String] $ttyrec_stealth_stdout_pattern                                   = $thebastion::params::ttyrec_stealth_stdout_pattern,
  Integer[0,default] $warn_before_kill_seconds                                      = $thebastion::params::warn_before_kill_seconds,
  Integer[0,default] $warn_before_lock_seconds                                      = $thebastion::params::warn_before_lock_seconds,

  # Addons parameters
  Integer[0,default] $backup_acl_keys_days_to_keep                                  = $thebastion::params::backup_acl_keys_days_to_keep,
  Stdlib::AbsolutePath $backup_acl_keys_destdir                                     = $thebastion::params::backup_acl_keys_destdir,
  Optional[String] $backup_acl_keys_gpgkeys                                         = $thebastion::params::backup_acl_keys_gpgkeys,
  Optional[String] $backup_acl_keys_logfacility                                     = $thebastion::params::backup_acl_keys_logfacility,
  Optional[Stdlib::AbsolutePath] $backup_acl_keys_logfile                           = $thebastion::params::backup_acl_keys_logfile,
  String $backup_acl_keys_push_options                                              = $thebastion::params::backup_acl_keys_push_options,
  String $backup_acl_keys_push_remote                                               = $thebastion::params::backup_acl_keys_push_remote,
  Stdlib::AbsolutePath $encrypt_rsync_and_move_to_directory                         = $thebastion::params::encrypt_rsync_and_move_to_directory,
  Integer[0,default] $encrypt_rsync_delay_before_remove_days                        = $thebastion::params::encrypt_rsync_delay_before_remove_days,
  Integer[0,default] $encrypt_rsync_move_delay_days                                 = $thebastion::params::encrypt_rsync_move_delay_days,
  String $encrypt_rsync_destination                                                 = $thebastion::params::encrypt_rsync_destination,
  Optional[Stdlib::AbsolutePath] $encrypt_rsync_logfile                             = $thebastion::params::encrypt_rsync_logfile,
  Array[Array[String]] $encrypt_rsync_recipients                                    = $thebastion::params::encrypt_rsync_recipients,
  String $encrypt_rsync_rsh                                                         = $thebastion::params::encrypt_rsync_rsh,
  Optional[String] $encrypt_rsync_signing_key                                       = $thebastion::params::encrypt_rsync_signing_key,
  Optional[String] $encrypt_rsync_signing_key_passphrase                            = $thebastion::params::encrypt_rsync_signing_key_passphrase,
  Optional[String] $encrypt_rsync_syslog_facility                                   = $thebastion::params::encrypt_rsync_syslog_facility,
  Array[String] $http_proxy_allowed_egress_protocols                                = $thebastion::params::http_proxy_allowed_egress_protocols,
  String $http_proxy_ciphers                                                        = $thebastion::params::http_proxy_ciphers,
  Boolean $http_proxy_enabled                                                       = $thebastion::params::http_proxy_enabled,
  Boolean $http_proxy_insecure                                                      = $thebastion::params::http_proxy_insecure,
  Integer[1,512] $http_proxy_min_servers                                            = $thebastion::params::http_proxy_min_servers,
  Integer[1,512] $http_proxy_min_spare_servers                                      = $thebastion::params::http_proxy_min_spare_servers,
  Integer[1,512] $http_proxy_max_servers                                            = $thebastion::params::http_proxy_max_servers,
  Integer[1,512] $http_proxy_max_spare_servers                                      = $thebastion::params::http_proxy_max_spare_servers,
  Integer[1,65535] $http_proxy_port                                                 = $thebastion::params::http_proxy_port,
  Stdlib::AbsolutePath $http_proxy_ssl_certificate                                  = $thebastion::params::http_proxy_ssl_certificate,
  Stdlib::AbsolutePath $http_proxy_ssl_key                                          = $thebastion::params::http_proxy_ssl_key,
  Integer $http_proxy_timeout                                                       = $thebastion::params::http_proxy_timeout,
  Optional[String] $piv_grace_reaper_syslog                                         = $thebastion::params::piv_grace_reaper_syslog,
  Boolean $sync_watcher_enabled                                                     = $thebastion::params::sync_watcher_enabled,
  Optional[Stdlib::AbsolutePath] $sync_watcher_logdir                               = $thebastion::params::sync_watcher_logdir,
  Array[String] $sync_watcher_remote_host_list                                      = $thebastion::params::sync_watcher_remote_host_list,
  String $sync_watcher_remote_user                                                  = $thebastion::params::sync_watcher_remote_user,
  String $sync_watcher_rsh_cmd                                                      = $thebastion::params::sync_watcher_rsh_cmd,
  String $sync_watcher_syslog                                                       = $thebastion::params::sync_watcher_syslog,
  Integer[0,default] $sync_watcher_timeout                                          = $thebastion::params::sync_watcher_timeout,
) inherits thebastion::params {
  contain ::thebastion::install
  contain ::thebastion::config
  contain ::thebastion::addons

  create_resources('thebastion::plugin', $plugins)

  Class['thebastion::install'] -> Class['thebastion::config'] -> Class['thebastion::addons']
}
