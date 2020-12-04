# @summary
#   Handles the bastion's addons to easily manage your production tasks
class thebastion::addons {
  assert_private()
  # Backup ACL keys, create folder to leave room for bastion's GPG setup

  file { '/etc/bastion/osh-backup-acl-keys.conf.d' :
    ensure => directory,
    owner  => 'root',
    group  => 'root',
    mode   => '0700',
  }

  file { '/etc/bastion/osh-backup-acl-keys.conf.d/01-managed-by-puppet.conf' :
    ensure  => file,
    owner   => 'root',
    group   => 'root',
    mode    => '0600',
    content => epp('thebastion/addons/osh-backup-acl-keys.conf.epp'),
  }

  # Encrypt and rsync tty records, create folder to leave room for bastion's GPG setup

  $encrypt_rsync_conf = {
    'encrypt_and_move_delay_days'     => $thebastion::encrypt_rsync_move_delay_days,
    'encrypt_and_move_to_directory'   => $thebastion::encrypt_rsync_and_move_to_directory,
    'logfile'                         => $thebastion::encrypt_rsync_logfile,
    'recipients'                      => $thebastion::encrypt_rsync_recipients,
    'rsync_delay_before_remove_days'  => $thebastion::encrypt_rsync_delay_before_remove_days,
    'rsync_destination'               => $thebastion::encrypt_rsync_destination,
    'rsync_rsh'                       => $thebastion::encrypt_rsync_rsh,
    'signing_key'                     => $thebastion::encrypt_rsync_signing_key,
    'signing_key_passphrase'          => $thebastion::encrypt_rsync_signing_key_passphrase,
    'syslog_facility'                 => $thebastion::encrypt_rsync_syslog_facility,
  }

  file { '/etc/bastion/osh-encrypt-rsync.conf.d' :
    ensure => directory,
    owner  => 'root',
    group  => 'root',
    mode   => '0700',
  }

  concat { '/etc/bastion/osh-encrypt-rsync.conf.d/01-managed-by-puppet.conf':
    ensure => present,
    owner  => 'root',
    group  => 'root',
    mode   => '0600',
  }

  concat::fragment { 'thebastion::addons::osh-encrypt-rsync-header':
    target  => '/etc/bastion/osh-encrypt-rsync.conf.d/01-managed-by-puppet.conf',
    content => "# Managed by puppet, do not edit\n",
    order   => '001',
  }

  concat::fragment { 'thebastion::addons::osh-encrypt-rsync-conf':
    target  => '/etc/bastion/osh-encrypt-rsync.conf.d/01-managed-by-puppet.conf',
    content => to_json_pretty($encrypt_rsync_conf, true),
    order   => '100',
  }

  # HTTP Proxy

  $http_proxy_conf = {
    'ciphers'           => $thebastion::http_proxy_ciphers,
    'enabled'           => $thebastion::http_proxy_enabled,
    'insecure'          => $thebastion::http_proxy_insecure,
    'min_servers'       => $thebastion::http_proxy_min_servers,
    'min_spare_servers' => $thebastion::http_proxy_min_spare_servers,
    'max_servers'       => $thebastion::http_proxy_max_servers,
    'max_spare_servers' => $thebastion::http_proxy_max_spare_servers,
    'port'              => $thebastion::http_proxy_port,
    'ssl_certificate'   => $thebastion::http_proxy_ssl_certificate,
    'ssl_key'           => $thebastion::http_proxy_ssl_key,
    'timeout'           => $thebastion::http_proxy_timeout,
  }

  concat { '/etc/bastion/osh-http-proxy.conf':
    ensure => present,
    owner  => 'root',
    group  => 'root',
    mode   => '0600',
  }

  concat::fragment { 'thebastion::addons::osh-http-proxy-header':
    target  => '/etc/bastion/osh-http-proxy.conf',
    content => "# Managed by puppet, do not edit\n",
    order   => '001',
  }

  concat::fragment { 'thebastion::addons::osh-http-proxy-conf':
    target  => '/etc/bastion/osh-http-proxy.conf',
    content => to_json_pretty($http_proxy_conf, true),
    order   => '100',
  }

  # Unit file, Service ?

  # PIV grace reaper

  $piv_grace_reaper_conf = {
    'SyslogFacility' => $thebastion::piv_grace_reaper_syslog,
  }

  concat { '/etc/bastion/osh-piv-grace-reaper.conf':
    ensure => present,
    owner  => 'root',
    group  => 'root',
    mode   => '0600',
  }

  concat::fragment { 'thebastion::addons::osh-piv-grace-reaper-header':
    target  => '/etc/bastion/osh-piv-grace-reaper.conf',
    content => "# Managed by puppet, do not edit\n",
    order   => '001',
  }

  concat::fragment { 'thebastion::addons::osh-piv-grace-reaper-conf':
    target  => '/etc/bastion/osh-piv-grace-reaper.conf',
    content => to_json_pretty($piv_grace_reaper_conf, true),
    order   => '100',
  }

  # Sync Watcher

  # Backup ACL keys, create folder to leave room for bastion's GPG setup

  # Shell has no boolean type, so convert to integer logic
  $sync_watcher_boolean_to_int = $thebastion::sync_watcher_enabled ? {
    true  => 1,
    false => 0
  }

  file { '/etc/bastion/osh-sync-watcher.sh' :
    ensure  => file,
    owner   => 'root',
    group   => 'root',
    mode    => '0600',
    content => epp('thebastion/addons/osh-sync-watcher.sh.epp', {
      enabled          => $sync_watcher_boolean_to_int,
      remote_host_list => $thebastion::sync_watcher_remote_host_list.join(' '),
    }),
  }

  file { '/etc/bastion/osh-sync-watcher.rsyncfilter' :
    ensure => file,
    owner  => 'root',
    group  => 'root',
    mode   => '0600',
    source => "${thebastion::bastion_basedir}/etc/bastion/osh-sync-watcher.rsyncfilter.dist",
  }
}
