# @summary Installs bastion software if enabled
#
class thebastion::install {
  assert_private()

  if $thebastion::install_thebastion {

    # Git is mandatory to clone bastion's repository
    ensure_packages(['git'])

    exec { 'Clone Thebastion':
      command => "git clone https://github.com/ovh/the-bastion ${thebastion::bastion_basedir}",
      unless  => "test -d ${thebastion::bastion_basedir}",
      path    => ['/usr/bin', '/bin'],
      require => Package['git'],
    }

    exec { 'Checkout Thebastion':
      command     => "git -C ${thebastion::bastion_basedir} $(git -C ${thebastion::bastion_basedir} tag | tail -1)",
      path        => ['/usr/bin', '/bin'],
      refreshonly => true,
      subscribe   => Exec['Clone Thebastion'],
    }

  }

  if $thebastion::install_packages {
    ensure_packages($thebastion::package_list)
  }

}
