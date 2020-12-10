# frozen_string_literal: true

# TODO : Acceptance test with real catalogue compiling

require 'spec_helper'
require 'json'

describe 'thebastion' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }

      describe 'with defaults' do
        it { is_expected.to compile.with_all_deps }
        it { is_expected.to create_class('thebastion') }
        it { is_expected.to contain_file('/etc/bastion') }
        it { is_expected.to contain_concat__fragment('thebastion-header').with_content(%r{^#}) }
        it { is_expected.to contain_concat__fragment('thebastion-conf') }
        it { is_expected.to contain_concat__fragment('thebastion-footer').with_content(%r{^#}) }
        it { is_expected.to contain_concat('/etc/bastion/bastion.conf') }
        it { is_expected.to contain_class('thebastion::addons').that_requires('Class[thebastion::config]') }
        it { is_expected.to contain_class('thebastion::config').that_requires('Class[thebastion::install]') }
        it { is_expected.to contain_class('thebastion::install') }
        it { is_expected.to contain_class('thebastion::params') }
      end

      context 'Thebastion Install validation' do
        it { is_expected.to contain_package('git').with_ensure('present') }
        it { is_expected.to contain_exec('Clone Thebastion').that_requires('Package[git]') }
        it { is_expected.to contain_exec('Checkout Thebastion').that_subscribes_to('Exec[Clone Thebastion]') }
      end

      context 'Thebastion No install validation' do
        let(:params) do
          {
            install_thebastion: false,
          }
        end

        it { is_expected.not_to contain_package('git') }
        it { is_expected.not_to contain_exec('Clone Thebastion') }
        it { is_expected.not_to contain_exec('Checkout Thebastion') }
      end

      context 'Dependencies Packages installation' do
        it { is_expected.to contain_package('acl').with_ensure('present') }
        it { is_expected.to contain_package('bash').with_ensure('present') }
        it { is_expected.to contain_package('binutils').with_ensure('present') }
        it { is_expected.to contain_package('cryptsetup').with_ensure('present') }
        it { is_expected.to contain_package('curl').with_ensure('present') }
        it { is_expected.to contain_package('expect').with_ensure('present') }
        it { is_expected.to contain_package('fping').with_ensure('present') }
        it { is_expected.to contain_package('gnupg').with_ensure('present') }
        it { is_expected.to contain_package('inotify-tools').with_ensure('present') }
        it { is_expected.to contain_package('lsof').with_ensure('present') }
        it { is_expected.to contain_package('mosh').with_ensure('present') }
        it { is_expected.to contain_package('openssh-server').with_ensure('present') }
        it { is_expected.to contain_package('pamtester').with_ensure('present') }
        it { is_expected.to contain_package('rsync').with_ensure('present') }
        it { is_expected.to contain_package('sudo').with_ensure('present') }
        case os_facts[:osfamily]
        when 'Debian'
          it { is_expected.to contain_package('coreutils').with_ensure('present') }
          it { is_expected.to contain_package('fortunes-bofh-excuses').with_ensure('present') }
          it { is_expected.to contain_package('iputils-ping').with_ensure('present') }
          it { is_expected.to contain_package('libcgi-pm-perl').with_ensure('present') }
          it { is_expected.to contain_package('libcommon-sense-perl').with_ensure('present') }
          it { is_expected.to contain_package('libdatetime-perl').with_ensure('present') }
          it { is_expected.to contain_package('libdbd-sqlite3-perl').with_ensure('present') }
          it { is_expected.to contain_package('libdigest-sha-perl').with_ensure('present') }
          it { is_expected.to contain_package('libgnupg-perl').with_ensure('present') }
          it { is_expected.to contain_package('libjson-perl').with_ensure('present') }
          it { is_expected.to contain_package('libjson-xs-perl').with_ensure('present') }
          it { is_expected.to contain_package('liblinux-prctl-perl').with_ensure('present') }
          it { is_expected.to contain_package('libnet-dns-perl').with_ensure('present') }
          it { is_expected.to contain_package('libnet-ip-perl').with_ensure('present') }
          it { is_expected.to contain_package('libnet-netmask-perl').with_ensure('present') }
          it { is_expected.to contain_package('libnet-server-perl').with_ensure('present') }
          it { is_expected.to contain_package('libnet-ssleay-perl').with_ensure('present') }
          it { is_expected.to contain_package('libpam-google-authenticator').with_ensure('present') }
          it { is_expected.to contain_package('libterm-readkey-perl').with_ensure('present') }
          it { is_expected.to contain_package('libterm-readline-gnu-perl').with_ensure('present') }
          it { is_expected.to contain_package('libtimedate-perl').with_ensure('present') }
          it { is_expected.to contain_package('libwww-perl').with_ensure('present') }
          it { is_expected.to contain_package('locales').with_ensure('present') }
          it { is_expected.to contain_package('netcat').with_ensure('present') }
          it { is_expected.to contain_package('sqlite3').with_ensure('present') }
          it { is_expected.to contain_package('xz-utils').with_ensure('present') }
          if (os_facts[:os]['name'] == 'Ubuntu' && ['14.04', '16.04'].include?(os_facts[:os]['release']['major'])) ||
             (os_facts[:os]['name'] == 'Debian' && os_facts[:os]['release']['major'] == '8')
            it { is_expected.to contain_package('openssh-blacklist').with_ensure('present') }
            it { is_expected.to contain_package('openssh-blacklist-extra').with_ensure('present') }
          end
        when 'RedHat'
          it { is_expected.to contain_package('cracklib-dicts').with_ensure('present') }
          it { is_expected.to contain_package('google-authenticator').with_ensure('present') }
          it { is_expected.to contain_package('nc').with_ensure('present') }
          it { is_expected.to contain_package('passwd').with_ensure('present') }
          it { is_expected.to contain_package('perl-CGI').with_ensure('present') }
          it { is_expected.to contain_package('perl-DateTime').with_ensure('present') }
          it { is_expected.to contain_package('perl-DBD-SQLite').with_ensure('present') }
          it { is_expected.to contain_package('perl-Digest').with_ensure('present') }
          it { is_expected.to contain_package('perl-JSON').with_ensure('present') }
          it { is_expected.to contain_package('perl-JSON-XS').with_ensure('present') }
          it { is_expected.to contain_package('perl-libwww-perl').with_ensure('present') }
          it { is_expected.to contain_package('perl-Net-DNS').with_ensure('present') }
          it { is_expected.to contain_package('perl-Net-IP').with_ensure('present') }
          it { is_expected.to contain_package('perl-Net-Netmask').with_ensure('present') }
          it { is_expected.to contain_package('perl-Net-Server').with_ensure('present') }
          it { is_expected.to contain_package('perl-Sys-Syslog').with_ensure('present') }
          it { is_expected.to contain_package('perl-TermReadKey').with_ensure('present') }
          it { is_expected.to contain_package('perl-Term-ReadLine-Gnu').with_ensure('present') }
          it { is_expected.to contain_package('perl(Test::More)').with_ensure('present') }
          it { is_expected.to contain_package('perl-TimeDate').with_ensure('present') }
          it { is_expected.to contain_package('perl-Time-HiRes').with_ensure('present') }
          it { is_expected.to contain_package('perl-Time-Piece').with_ensure('present') }
          it { is_expected.to contain_package('qrencode-libs').with_ensure('present') }
          it { is_expected.to contain_package('sqlite').with_ensure('present') }
          it { is_expected.to contain_package('which').with_ensure('present') }
          it { is_expected.to contain_package('xz').with_ensure('present') }
          if os_facts[:operatingsystemmajrelease] == '7'
            it { is_expected.to contain_package('coreutils') }
            it { is_expected.to contain_package('fortune-mod') }
          end
        end
      end

      # Bastion config tests

      context 'Valid configuration validation' do
        let(:params) do
          {
            account_create_default_personal_accesses: ['ACCOUNT@127.0.0.1', 'root@192.0.2.2/32'],
            account_create_supplementary_groups:      ['osh-accountListEgressKeys', 'osh-realmList'],
            account_expired_message:                  'Hello there',
            account_external_validation_program:      '$BASEDIR/bin/other/check-active-account-simple.pl',
            account_ext_validation_deny_on_failure:   true,
            account_max_inactive_days:                90,
            account_mfapolicy:                        'enabled',
            account_uid_max:                          99_999,
            account_uid_min:                          2000,
            admin_accounts:                           ['john', 'doe'],
            allowed_egress_ssh_algorithms:            ['ecdsa', 'ed25519'],
            allowed_ingress_ssh_algorithms:           ['rsa', 'dsa'],
            allowed_networks:                         ['192.0.2.2', '192.0.1.0/24'],
            always_active_accounts:                   ['rob', 'bot'],
            bastion_identifier:                       'my.little.pony',
            bastion_listen_port:                      222,
            bastion_name:                             'mlp',
            debug:                                    true,
            default_account_egress_key_algorithm:     'rsa',
            default_account_egress_key_size:          4096,
            default_login:                            'root',
            display_last_login:                       false,
            documentation_url:                        'http://my.cutiedoc.com/bastion/',
            egress_keys_from:                         ['127.0.0.1', '192.0.1.0/24'],
            enable_account_access_log:                false,
            enable_account_sql_log:                   false,
            enable_global_access_log:                 false,
            enable_global_sql_log:                    false,
            enable_syslog:                            false,
            forbidden_networks:                       ['192.0.2.3', '192.0.1.0/24'],
            idle_kill_timeout:                        90,
            idle_lock_timeout:                        14,
            ingress_keys_from_allow_override:         true,
            ingress_keys_from:                        ['192.0.2.4', '192.0.1.0/24'],
            ingress_to_egress_rules:                  [[['10.19.0.0/16', '10.15.15.0/24'], ['10.20.0.0/16'], 'ALLOW-EXCLUSIVE']],
            interactive_mode_allowed:                 true,
            interactive_mode_timeout:                 60,
            keyboard_interactive_allowed:             true,
            maximum_ingress_rsa_key_size:             4096,
            maximum_egress_rsa_key_size:              4095,
            minimum_ingress_rsa_key_size:             2048,
            minimum_egress_rsa_key_size:              2047,
            mfa_password_inactive_days:               5,
            mfa_password_max_days:                    90,
            mfa_password_min_days:                    6,
            mfa_password_warn_days:                   14,
            mfa_post_command:                         ['sudo', '-n', '-u', 'root', '--', '/sbin/pam_tally2', '-u', '%ACCOUNT%', '-r'],
            mosh_allowed:                             true,
            mosh_command_line:                        '-s -p 40000:49999',
            mosh_timeout_network:                     50,
            mosh_timeout_signal:                      42,
            password_allowed:                         true,
            read_only_slave_mode:                     true,
            remote_command_escape_by_default:         true,
            ssh_client_debug_level:                   2,
            ssh_client_has_option_e:                  true,
            super_owner_accounts:                     ['john', 'doe'],
            syslog_description:                       'thebastion',
            syslog_facility:                          'local0',
            telnet_allowed:                           true,
            ttyrec_additional_parameters:             ['my', 'little', 'param'],
            ttyrec_filename_format:                   '%Y-%m-%d',
            ttyrec_group_id_offset:                   100_000,
            warn_before_kill_seconds:                 42,
            warn_before_lock_seconds:                 41,
          }
        end

        it 'tests valid parameters input' do
          parsed = JSON.parse(catalogue.resource('concat::fragment', 'thebastion-conf').send(:parameters)[:content])
          expect(parsed['accountCreateDefaultPersonalAccesses']).to contain_exactly('ACCOUNT@127.0.0.1', 'root@192.0.2.2/32')
          expect(parsed['accountCreateSupplementaryGroups']).to contain_exactly('osh-accountListEgressKeys', 'osh-realmList')
          expect(parsed['accountExpiredMessage']).to eq('Hello there')
          expect(parsed['accountExternalValidationProgram']).to eq('$BASEDIR/bin/other/check-active-account-simple.pl')
          expect(parsed['accountExternalValidationDenyOnFailure']).to be true
          expect(parsed['accountMaxInactiveDays']).to eq(90)
          expect(parsed['accountMFAPolicy']).to eq('enabled')
          expect(parsed['accountUidMax']).to eq(99_999)
          expect(parsed['accountUidMin']).to eq(2000)
          expect(parsed['adminAccounts']).to contain_exactly('john', 'doe')
          expect(parsed['allowedEgressSshAlgorithms']).to contain_exactly('ecdsa', 'ed25519')
          expect(parsed['allowedIngressSshAlgorithms']).to contain_exactly('rsa', 'dsa')
          expect(parsed['allowedNetworks']).to contain_exactly('192.0.2.2', '192.0.1.0/24')
          expect(parsed['alwaysActiveAccounts']).to contain_exactly('rob', 'bot')
          expect(parsed['bastionCommand']).to eq('ssh ACCOUNT@my.little.pony -p 222 -t -- ')
          expect(parsed['bastionName']).to eq('mlp')
          expect(parsed['debug']).to be true
          expect(parsed['defaultAccountEgressKeyAlgorithm']).to eq('rsa')
          expect(parsed['defaultAccountEgressKeySize']).to eq(4096)
          expect(parsed['defaultLogin']).to eq('root')
          expect(parsed['displayLastLogin']).to be false
          expect(parsed['documentationURL']).to eq('http://my.cutiedoc.com/bastion/')
          expect(parsed['enableAccountAccessLog']).to be false
          expect(parsed['enableAccountSqlLog']).to be false
          expect(parsed['enableGlobalAccessLog']).to be false
          expect(parsed['enableGlobalSqlLog']).to be false
          expect(parsed['enableSyslog']).to be false
          expect(parsed['egressKeysFrom']).to contain_exactly('127.0.0.1', '192.0.1.0/24')
          expect(parsed['forbiddenNetworks']).to contain_exactly('192.0.2.3', '192.0.1.0/24')
          expect(parsed['idleKillTimeout']).to eq(90)
          expect(parsed['idleLockTimeout']).to eq(14)
          expect(parsed['ingressKeysFrom']).to contain_exactly('192.0.2.4', '192.0.1.0/24')
          expect(parsed['ingressKeysFromAllowOverride']).to be true
          expect(parsed['ingressToEgressRules']).to contain_exactly([['10.19.0.0/16', '10.15.15.0/24'], ['10.20.0.0/16'], 'ALLOW-EXCLUSIVE'])
          expect(parsed['interactiveModeAllowed']).to be true
          expect(parsed['interactiveModeTimeout']).to eq(60)
          expect(parsed['keyboardInteractiveAllowed']).to be true
          expect(parsed['maximumIngressRsaKeySize']).to eq(4096)
          expect(parsed['maximumEgressRsaKeySize']).to eq(4095)
          expect(parsed['minimumIngressRsaKeySize']).to eq(2048)
          expect(parsed['minimumEgressRsaKeySize']).to eq(2047)
          expect(parsed['MFAPasswordInactiveDays']).to eq(5)
          expect(parsed['MFAPasswordMaxDays']).to eq(90)
          expect(parsed['MFAPasswordMinDays']).to eq(6)
          expect(parsed['MFAPasswordWarnDays']).to eq(14)
          expect(parsed['MFAPostCommand']).to contain_exactly('sudo', '-n', '-u', 'root', '--', '/sbin/pam_tally2', '-u', '%ACCOUNT%', '-r')
          expect(parsed['moshAllowed']).to be true
          expect(parsed['moshCommandLine']).to eq('-s -p 40000:49999')
          expect(parsed['moshTimeoutNetwork']).to eq(50)
          expect(parsed['moshTimeoutSignal']).to eq(42)
          expect(parsed['passwordAllowed']).to be true
          expect(parsed['readOnlySlaveMode']).to be true
          expect(parsed['remoteCommandEscapeByDefault']).to be true
          expect(parsed['sshClientDebugLevel']).to eq(2)
          expect(parsed['sshClientHasOptionE']).to be true
          expect(parsed['superOwnerAccounts']).to contain_exactly('john', 'doe')
          expect(parsed['syslogDescription']).to eq('thebastion')
          expect(parsed['syslogFacility']).to eq('local0')
          expect(parsed['telnetAllowed']).to be true
          expect(parsed['ttyrecAdditionalParameters']).to contain_exactly('my', 'little', 'param')
          expect(parsed['ttyrecFilenameFormat']).to eq('%Y-%m-%d')
          expect(parsed['ttyrecGroupIdOffset']).to eq(100_000)
          expect(parsed['warnBeforeKillSeconds']).to eq(42)
          expect(parsed['warnBeforeLockSeconds']).to eq(41)
        end
        it { is_expected.to contain_exec('add_john_in_osh-admin_group').with_command('getent passwd john >/dev/null && usermod -a -G osh-admin john') }
        it { is_expected.to contain_exec('add_john_in_osh-admin_group').with_unless('id -nG john | grep -q \'osh-admin\'') }
        it { is_expected.to contain_exec('add_doe_in_osh-admin_group').with_command('getent passwd doe >/dev/null && usermod -a -G osh-admin doe') }
        it { is_expected.to contain_exec('add_doe_in_osh-admin_group').with_unless('id -nG doe | grep -q \'osh-admin\'') }
      end

      context 'Invalid configuration validation' do
        let(:params) do
          {
            account_create_default_personal_accesses: 'invalid@127.0.0.1',
            account_create_supplementary_groups:      'osh-invalid',
            account_expired_message:                  42,
            account_external_validation_program:      14,
            account_ext_validation_deny_on_failure:   'no',
            account_max_inactive_days:                -1,
            account_mfapolicy:                        'false',
            account_uid_max:                          -42,
            account_uid_min:                          -1,
            admin_accounts:                           'tagazou',
            allowed_egress_ssh_algorithms:            ['ec25519'],
            allowed_ingress_ssh_algorithms:           ['rda'],
            allowed_networks:                         ['root@127.0.0.1'],
            always_active_accounts:                   'mybot',
            bastion_identifier:                       '192.0.2.2/32',
            bastion_listen_port:                      -1,
            bastion_name:                             42,
            debug:                                    'no',
            default_account_egress_key_algorithm:     'rda',
            default_account_egress_key_size:          16_384,
            default_login:                            42,
            display_last_login:                       'yes',
            documentation_url:                        'https:/my.sypertypo.org/bastion/',
            enable_account_access_log:                'yes',
            enable_account_sql_log:                   'yes',
            enable_global_access_log:                 'yes',
            enable_global_sql_log:                    'yes',
            enable_syslog:                            'yes',
            egress_keys_from:                         '192.0.2.2/32',
            forbidden_networks:                       ['root@127.0.0.1'],
            idle_kill_timeout:                        -1,
            idle_lock_timeout:                        -1,
            ingress_keys_from:                        ['root@127.0.0.1'],
            ingress_keys_from_allow_override:         'yes',
            ingress_to_egress_rules:                  '127.0.0.1, 127.0.0.1, ALLOW',
            interactive_mode_allowed:                 'yes',
            interactive_mode_timeout:                 -1,
            keyboard_interactive_allowed:             'no',
            maximum_ingress_rsa_key_size:             -1,
            maximum_egress_rsa_key_size:              -1,
            minimum_ingress_rsa_key_size:             -1,
            minimum_egress_rsa_key_size:              -1,
            mfa_password_inactive_days:               -42,
            mfa_password_max_days:                    -42,
            mfa_password_min_days:                    -42,
            mfa_password_warn_days:                   -42,
            mfa_post_command:                         'My awesome post pam command',
            mosh_allowed:                             'no',
            mosh_command_line:                        ['-s', '-p', 40_000, 49_999],
            mosh_timeout_network:                     -1,
            mosh_timeout_signal:                      -1,
            password_allowed:                         'no',
            read_only_slave_mode:                     'yes',
            remote_command_escape_by_default:         'yes',
            ssh_client_debug_level:                   5,
            ssh_client_has_option_e:                  'yes',
            super_owner_accounts:                     'johnny',
            syslog_description:                       true,
            syslog_facility:                          false,
            telnet_allowed:                           'no',
            ttyrec_additional_parameters:             'my little param',
            ttyrec_filename_format:                   ['%Y', '%m', '%d'],
            ttyrec_group_id_offset:                   1000,
            warn_before_kill_seconds:                 -42,
            warn_before_lock_seconds:                 -41,
          }
        end

        it { is_expected.to compile.and_raise_error(%r{account_create_default_personal_accesses}) }
        it { is_expected.to compile.and_raise_error(%r{account_create_supplementary_groups}) }
        it { is_expected.to compile.and_raise_error(%r{account_expired_message}) }
        it { is_expected.to compile.and_raise_error(%r{account_external_validation_program}) }
        it { is_expected.to compile.and_raise_error(%r{account_ext_validation_deny_on_failure}) }
        it { is_expected.to compile.and_raise_error(%r{account_max_inactive_days}) }
        it { is_expected.to compile.and_raise_error(%r{account_mfapolicy}) }
        it { is_expected.to compile.and_raise_error(%r{account_uid_max}) }
        it { is_expected.to compile.and_raise_error(%r{account_uid_min}) }
        it { is_expected.to compile.and_raise_error(%r{admin_accounts}) }
        it { is_expected.to compile.and_raise_error(%r{allowed_egress_ssh_algorithms}) }
        it { is_expected.to compile.and_raise_error(%r{allowed_ingress_ssh_algorithms}) }
        it { is_expected.to compile.and_raise_error(%r{allowed_networks}) }
        it { is_expected.to compile.and_raise_error(%r{always_active_accounts}) }
        it { is_expected.to compile.and_raise_error(%r{bastion_identifier}) }
        it { is_expected.to compile.and_raise_error(%r{bastion_listen_port}) }
        it { is_expected.to compile.and_raise_error(%r{bastion_name}) }
        it { is_expected.to compile.and_raise_error(%r{debug}) }
        it { is_expected.to compile.and_raise_error(%r{default_account_egress_key_algorithm}) }
        it { is_expected.to compile.and_raise_error(%r{default_account_egress_key_size}) }
        it { is_expected.to compile.and_raise_error(%r{default_login}) }
        it { is_expected.to compile.and_raise_error(%r{display_last_login}) }
        it { is_expected.to compile.and_raise_error(%r{documentation_url}) }
        it { is_expected.to compile.and_raise_error(%r{egress_keys_from}) }
        it { is_expected.to compile.and_raise_error(%r{enable_account_access_log}) }
        it { is_expected.to compile.and_raise_error(%r{enable_account_sql_log}) }
        it { is_expected.to compile.and_raise_error(%r{enable_global_access_log}) }
        it { is_expected.to compile.and_raise_error(%r{enable_global_sql_log}) }
        it { is_expected.to compile.and_raise_error(%r{enable_syslog}) }
        it { is_expected.to compile.and_raise_error(%r{forbidden_networks}) }
        it { is_expected.to compile.and_raise_error(%r{idle_kill_timeout}) }
        it { is_expected.to compile.and_raise_error(%r{idle_lock_timeout}) }
        it { is_expected.to compile.and_raise_error(%r{ingress_keys_from}) }
        it { is_expected.to compile.and_raise_error(%r{ingress_keys_from_allow_override}) }
        it { is_expected.to compile.and_raise_error(%r{ingress_to_egress_rules}) }
        it { is_expected.to compile.and_raise_error(%r{interactive_mode_allowed}) }
        it { is_expected.to compile.and_raise_error(%r{interactive_mode_timeout}) }
        it { is_expected.to compile.and_raise_error(%r{keyboard_interactive_allowed}) }
        it { is_expected.to compile.and_raise_error(%r{maximum_ingress_rsa_key_size}) }
        it { is_expected.to compile.and_raise_error(%r{maximum_egress_rsa_key_size}) }
        it { is_expected.to compile.and_raise_error(%r{minimum_ingress_rsa_key_size}) }
        it { is_expected.to compile.and_raise_error(%r{minimum_egress_rsa_key_size}) }
        it { is_expected.to compile.and_raise_error(%r{mfa_password_inactive_days}) }
        it { is_expected.to compile.and_raise_error(%r{mfa_password_max_days}) }
        it { is_expected.to compile.and_raise_error(%r{mfa_password_min_days}) }
        it { is_expected.to compile.and_raise_error(%r{mfa_password_warn_days}) }
        it { is_expected.to compile.and_raise_error(%r{mfa_post_command}) }
        it { is_expected.to compile.and_raise_error(%r{mosh_allowed}) }
        it { is_expected.to compile.and_raise_error(%r{mosh_command_line}) }
        it { is_expected.to compile.and_raise_error(%r{mosh_timeout_network}) }
        it { is_expected.to compile.and_raise_error(%r{mosh_timeout_signal}) }
        it { is_expected.to compile.and_raise_error(%r{password_allowed}) }
        it { is_expected.to compile.and_raise_error(%r{read_only_slave_mode}) }
        it { is_expected.to compile.and_raise_error(%r{remote_command_escape_by_default}) }
        it { is_expected.to compile.and_raise_error(%r{ssh_client_debug_level}) }
        it { is_expected.to compile.and_raise_error(%r{ssh_client_has_option_e}) }
        it { is_expected.to compile.and_raise_error(%r{super_owner_accounts}) }
        it { is_expected.to compile.and_raise_error(%r{syslog_description}) }
        it { is_expected.to compile.and_raise_error(%r{syslog_facility}) }
        it { is_expected.to compile.and_raise_error(%r{telnet_allowed}) }
        it { is_expected.to compile.and_raise_error(%r{ttyrec_additional_parameters}) }
        it { is_expected.to compile.and_raise_error(%r{ttyrec_filename_format}) }
        it { is_expected.to compile.and_raise_error(%r{ttyrec_group_id_offset}) }
        it { is_expected.to compile.and_raise_error(%r{warn_before_kill_seconds}) }
        it { is_expected.to compile.and_raise_error(%r{warn_before_lock_seconds}) }
      end

      context 'Uid range' do
        let(:params) do
          {
            account_uid_max: 5000,
            account_uid_min: 5000,
          }
        end

        it { is_expected.to compile.and_raise_error(%r{account_uid_max must be strictly superior than account_uid_min}) }
      end

      context 'RSA key size invalidation' do
        let(:params) do
          {
            default_account_egress_key_algorithm: 'rsa',
            default_account_egress_key_size:      1024,
          }
        end

        it { is_expected.to compile.and_raise_error(%r{When default_account_egress_key_algorithm is set to rsa, default_account_egress_key_size must be between 2048 and 8192}) }
      end

      context 'ECDSA key size invalidation' do
        let(:params) do
          {
            default_account_egress_key_algorithm: 'ecdsa',
            default_account_egress_key_size:      1024,
          }
        end

        it { is_expected.to compile.and_raise_error(%r{When default_account_egress_key_algorithm is set to ecdsa, default_account_egress_key_size must be 256, 384 or 521}) }
      end

      context 'ED25519 key size invalidation' do
        let(:params) do
          {
            default_account_egress_key_algorithm: 'ed25519',
            default_account_egress_key_size:      4096,
          }
        end

        it { is_expected.to compile.and_raise_error(%r{When default_account_egress_key_algorithm is set to ed25519, default_account_egress_key_size must be 256}) }
      end

      context 'Lock and kill timeout' do
        let(:params) do
          {
            idle_kill_timeout: 1990,
            idle_lock_timeout: 1990,
          }
        end

        it { is_expected.to compile.and_raise_error(%r{When set to non-zero integers, idle_kill_timeout must be strictly higher than idle_lock_timeout}) }
      end

      context 'Ingress to Egress data type validation (1st item)' do
        let(:params) do
          {
            ingress_to_egress_rules: [['10.19.0.0/16', '10.20.0.0/16', 'allow']],
          }
        end

        it { is_expected.to compile.and_raise_error(%r{First item of each rule inside ingress_to_egress_rules must be an array of IPv4 elements.}) }
      end

      context 'Ingress to Egress data type validation (2nd item)' do
        let(:params) do
          {
            ingress_to_egress_rules: [[['10.19.0.0/16', '10.15.15.0/24'], '10.20.0.0/16', 'allow']],
          }
        end

        it { is_expected.to compile.and_raise_error(%r{Second item of each rule inside ingress_to_egress_rules must be an array of IPv4 elements.}) }
      end

      context 'Ingress to Egress data type validation (3rd item)' do
        let(:params) do
          {
            ingress_to_egress_rules: [[['10.19.0.0/16', '10.15.15.0/24'], ['10.20.0.0/16'], 'allow']],
          }
        end

        it { is_expected.to compile.and_raise_error(%r{Third item of each rule inside ingress_to_egress_rules must have value in DENY, ALLOW, ALLOW-EXCLUSIVE.}) }
      end

      context 'Egress RSA sizes' do
        let(:params) do
          {
            maximum_egress_rsa_key_size: 1406,
            minimum_egress_rsa_key_size: 1990,
          }
        end

        it { is_expected.to compile.and_raise_error(%r{maximum_egress_rsa_key_size must be superior than minimum_egress_rsa_key_size}) }
      end

      context 'Ingress RSA sizes' do
        let(:params) do
          {
            maximum_ingress_rsa_key_size: 1406,
            minimum_ingress_rsa_key_size: 1990,
          }
        end

        it { is_expected.to compile.and_raise_error(%r{maximum_ingress_rsa_key_size must be superior than minimum_ingress_rsa_key_size}) }
      end

      # Bastion plugins tests
      context 'Plugin Instanciation' do
        let(:params) do
          {
            plugins: {
              'selfResetIngressKeys' => {
                'configuration' => {
                  'disabled'     => true,
                  'mfa_required' => 'totp',
                },
              },
              'selfGeneratePassword' => {
                'configuration' => {
                  'disabled'     => true,
                  'mfa_required' => 'totp',
                },
              },
            },
          }
        end

        it { is_expected.to contain_thebastion__plugin('selfResetIngressKeys') }
        it { is_expected.to contain_concat('/etc/bastion/plugin.selfGeneratePassword.conf') }
        it { is_expected.to contain_concat__fragment('thebastion-plugin-selfResetIngressKeys-conf') }
        it { is_expected.to contain_concat__fragment('thebastion-plugin-selfResetIngressKeys-header') }
        it { is_expected.to contain_thebastion__plugin('selfGeneratePassword') }
        it { is_expected.to contain_concat('/etc/bastion/plugin.selfResetIngressKeys.conf') }
        it { is_expected.to contain_concat__fragment('thebastion-plugin-selfGeneratePassword-conf') }
        it { is_expected.to contain_concat__fragment('thebastion-plugin-selfGeneratePassword-header') }
      end

      # Bastion addons tests

      it { is_expected.to contain_file('/etc/bastion/osh-backup-acl-keys.conf.d') }
      it { is_expected.to contain_file('/etc/bastion/osh-backup-acl-keys.conf.d/01-managed-by-puppet.conf') }
      it { is_expected.to contain_file('/etc/bastion/osh-backup-acl-keys.conf.d/01-managed-by-puppet.conf').without_content(%r{^GPGKEYS}) }
      it { is_expected.to contain_file('/etc/bastion/osh-backup-acl-keys.conf.d/01-managed-by-puppet.conf').without_content(%r{^LOG_FACILITY}) }
      it { is_expected.to contain_file('/etc/bastion/osh-backup-acl-keys.conf.d/01-managed-by-puppet.conf').without_content(%r{^LOGFILE}) }
      it { is_expected.to contain_file('/etc/bastion/osh-encrypt-rsync.conf.d') }
      it { is_expected.to contain_concat('/etc/bastion/osh-encrypt-rsync.conf.d/01-managed-by-puppet.conf') }
      it { is_expected.to contain_concat__fragment('thebastion::addons::osh-encrypt-rsync-header').with_content(%r{^#}) }
      it { is_expected.to contain_concat__fragment('thebastion::addons::osh-encrypt-rsync-conf') }
      it { is_expected.to contain_concat__fragment('thebastion::addons::osh-encrypt-rsync-conf').without_content(%r{^logfile}) }
      it { is_expected.to contain_concat__fragment('thebastion::addons::osh-encrypt-rsync-conf').without_content(%r{^signing_key}) }
      it { is_expected.to contain_concat__fragment('thebastion::addons::osh-encrypt-rsync-conf').without_content(%r{^signing_key_passphrase}) }
      it { is_expected.to contain_concat__fragment('thebastion::addons::osh-encrypt-rsync-conf').without_content(%r{^syslog_facility}) }
      it { is_expected.to contain_concat('/etc/bastion/osh-http-proxy.conf') }
      it { is_expected.to contain_concat__fragment('thebastion::addons::osh-http-proxy-header').with_content(%r{^#}) }
      it { is_expected.to contain_concat__fragment('thebastion::addons::osh-http-proxy-conf') }
      it { is_expected.to contain_concat('/etc/bastion/osh-piv-grace-reaper.conf') }
      it { is_expected.to contain_concat__fragment('thebastion::addons::osh-piv-grace-reaper-header').with_content(%r{^#}) }
      it { is_expected.to contain_concat__fragment('thebastion::addons::osh-piv-grace-reaper-conf').without_content(%r{^SyslogFacility}) }
      it { is_expected.to contain_file('/etc/bastion/osh-sync-watcher.sh') }
      it { is_expected.to contain_file('/etc/bastion/osh-sync-watcher.sh').without_content(%r{^logdir}) }
      it { is_expected.to contain_file('/etc/bastion/osh-sync-watcher.rsyncfilter') }

      context 'osh-backup-acl-keys configuration validation' do
        let(:params) do
          {
            backup_acl_keys_days_to_keep: 42,
            backup_acl_keys_destdir:      '/tmp/myfile',
            backup_acl_keys_gpgkeys:      'C8CDE9CD9CE7B564',
            backup_acl_keys_logfacility:  'local3',
            backup_acl_keys_logfile:      '/var/addon.log',
            backup_acl_keys_push_options: '-i HOME/.ssh/id_backup',
            backup_acl_keys_push_remote:  'push@1.2.3.4:~/backup/',
          }
        end

        it { is_expected.to contain_file('/etc/bastion/osh-backup-acl-keys.conf.d/01-managed-by-puppet.conf').with_content(%r{^DAYSTOKEEP=42$}) }
        it { is_expected.to contain_file('/etc/bastion/osh-backup-acl-keys.conf.d/01-managed-by-puppet.conf').with_content(%r{^DESTDIR=/tmp/myfile$}) }
        it { is_expected.to contain_file('/etc/bastion/osh-backup-acl-keys.conf.d/01-managed-by-puppet.conf').with_content(%r{^GPGKEYS="C8CDE9CD9CE7B564"$}) }
        it { is_expected.to contain_file('/etc/bastion/osh-backup-acl-keys.conf.d/01-managed-by-puppet.conf').with_content(%r{^LOG_FACILITY="local3"$}) }
        it { is_expected.to contain_file('/etc/bastion/osh-backup-acl-keys.conf.d/01-managed-by-puppet.conf').with_content(%r{^LOGFILE="/var/addon.log"$}) }
        it { is_expected.to contain_file('/etc/bastion/osh-backup-acl-keys.conf.d/01-managed-by-puppet.conf').with_content(%r{^PUSH_REMOTE="push@1.2.3.4:~/backup/"$}) }
        it { is_expected.to contain_file('/etc/bastion/osh-backup-acl-keys.conf.d/01-managed-by-puppet.conf').with_content(%r{^PUSH_OPTIONS="-i HOME/.ssh/id_backup"$}) }
      end

      context 'osh-encrypt-rsync configuration validation' do
        let(:params) do
          {
            encrypt_rsync_and_move_to_directory:    '/tmp/myfolder',
            encrypt_rsync_delay_before_remove_days: 42,
            encrypt_rsync_move_delay_days:          12,
            encrypt_rsync_destination:              'myuser@myhost:~/ttyrec/',
            encrypt_rsync_logfile:                  '/var/log/my.log',
            encrypt_rsync_recipients:               [['AAAAAAAA', 'BBBBBBBB']],
            encrypt_rsync_rsh:                      'ssh -i /home/my/super/rsa',
            encrypt_rsync_signing_key:              'AAAAAAAA',
            encrypt_rsync_signing_key_passphrase:   'my_awesome_passphrase',
            encrypt_rsync_syslog_facility:          'local3',
          }
        end

        it 'tests valid parameters input' do
          parsed = JSON.parse(catalogue.resource('concat::fragment', 'thebastion::addons::osh-encrypt-rsync-conf').send(:parameters)[:content])
          expect(parsed['encrypt_and_move_delay_days']).to eq(12)
          expect(parsed['encrypt_and_move_to_directory']).to eq('/tmp/myfolder')
          expect(parsed['logfile']).to eq('/var/log/my.log')
          expect(parsed['recipients']).to contain_exactly(['AAAAAAAA', 'BBBBBBBB'])
          expect(parsed['rsync_delay_before_remove_days']).to eq(42)
          expect(parsed['rsync_destination']).to eq('myuser@myhost:~/ttyrec/')
          expect(parsed['rsync_rsh']).to eq('ssh -i /home/my/super/rsa')
          expect(parsed['signing_key']).to eq('AAAAAAAA')
          expect(parsed['signing_key_passphrase']).to eq('my_awesome_passphrase')
          expect(parsed['syslog_facility']).to eq('local3')
        end
      end

      context 'osh-http-proxy configuration validation' do
        let(:params) do
          {
            http_proxy_ciphers:           'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384',
            http_proxy_enabled:           true,
            http_proxy_insecure:          true,
            http_proxy_min_servers:       20,
            http_proxy_min_spare_servers: 12,
            http_proxy_max_servers:       20,
            http_proxy_max_spare_servers: 18,
            http_proxy_port:              7,
            http_proxy_ssl_certificate:   '/tmp/certs/mycert',
            http_proxy_ssl_key:           '/tmp/certs/mykey',
            http_proxy_timeout:           85,
          }
        end

        it 'tests valid parameters input' do
          parsed = JSON.parse(catalogue.resource('concat::fragment', 'thebastion::addons::osh-http-proxy-conf').send(:parameters)[:content])
          expect(parsed['ciphers']).to eq('ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384')
          expect(parsed['enabled']).to be true
          expect(parsed['insecure']).to be true
          expect(parsed['min_servers']).to eq(20)
          expect(parsed['min_spare_servers']).to eq(12)
          expect(parsed['max_servers']).to eq(20)
          expect(parsed['max_spare_servers']).to eq(18)
          expect(parsed['port']).to eq(7)
          expect(parsed['ssl_certificate']).to eq('/tmp/certs/mycert')
          expect(parsed['ssl_key']).to eq('/tmp/certs/mykey')
          expect(parsed['timeout']).to eq(85)
        end
      end

      context 'osh-piv-grace-reaper configuration validation' do
        let(:params) do
          {
            piv_grace_reaper_syslog: 'local6',
          }
        end

        it 'tests valid parameters input' do
          parsed = JSON.parse(catalogue.resource('concat::fragment', 'thebastion::addons::osh-piv-grace-reaper-conf').send(:parameters)[:content])
          expect(parsed['SyslogFacility']).to eq('local6')
        end
      end

      context 'osh-sync-watcher configuration validation' do
        let(:params) do
          {
            sync_watcher_enabled:          false,
            sync_watcher_logdir:           '/var/log/bastion',
            sync_watcher_remote_host_list: ['127.0.0.1', '127.0.0.2:222'],
            sync_watcher_remote_user:      'bastionsync',
            sync_watcher_rsh_cmd:          'ssh -q -i /root/.ssh/id_master2slave',
            sync_watcher_syslog:           'local6',
            sync_watcher_timeout:          180,
          }
        end

        it { is_expected.to contain_file('/etc/bastion/osh-sync-watcher.sh').with_content(%r{^enabled=0$}) }
        it { is_expected.to contain_file('/etc/bastion/osh-sync-watcher.sh').with_content(%r{^logdir=/var/log/bastion$}) }
        it { is_expected.to contain_file('/etc/bastion/osh-sync-watcher.sh').with_content(%r{^remotehostlist="127.0.0.1 127.0.0.2:222"$}) }
        it { is_expected.to contain_file('/etc/bastion/osh-sync-watcher.sh').with_content(%r{^remoteuser=bastionsync$}) }
        it { is_expected.to contain_file('/etc/bastion/osh-sync-watcher.sh').with_content(%r{^rshcmd="ssh -q -i /root/.ssh/id_master2slave"$}) }
        it { is_expected.to contain_file('/etc/bastion/osh-sync-watcher.sh').with_content(%r{^syslog=local6$}) }
        it { is_expected.to contain_file('/etc/bastion/osh-sync-watcher.sh').with_content(%r{^timeout=180$}) }
      end
    end
  end
end
