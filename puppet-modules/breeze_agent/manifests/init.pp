class breeze_agent (
  $breeze_package_linux   = $::breeze_package_linux,
  $breeze_package_windows = $::breeze_package_windows,
) {

  if $kernel == 'Linux' {

    file { 'breeze-agent':
      path   => "/tmp/breeze-agent.linux.tgz",
      ensure => present,
      source => "puppet:///modules/breeze_agent/${breeze_package_linux}",
    }

    exec { 'unpack-breeze':
      path    => ['/usr/bin', '/usr/sbin', '/bin', '/usr/local/sbin', '/sbin'],
      command => "tar zxf /tmp/breeze-agent.linux.tgz -C /opt",
      creates => "/opt/breeze-agent/app.rb",
      require => File['breeze-agent'],
    }

    file { 'cron-file':
      path    => "/etc/cron.d/breeze-agent",
      ensure  => present,
      require => Exec['unpack-breeze'],
      content => "*/15 * * * * root /opt/breeze-agent/app.sh >> /var/log/breeze-agent.log 2>&1\n",
    }

  } else {

      file { 'breeze-agent':
        path   => "C:\\breeze-agent.exe",
        ensure => present,
        source => "puppet:///modules/breeze_agent/${breeze_package_windows}",
      }

      exec { "install-breeze":
        command => "C:\\breeze-agent.exe",
        creates => "C:\\Program Files\\Breeze\\app.bat",
      }
    }

}
