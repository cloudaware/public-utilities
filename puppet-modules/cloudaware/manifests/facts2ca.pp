class cloudaware::facts2ca (
  $facts2ca_s3_bucket  = $::facts2ca_s3_bucket,
  $_facts2ca_s3_region = $::facts2ca_s3_region,
  $facts2ca_access_key = $::facts2ca_access_key,
  $facts2ca_secret_key = $::facts2ca_secret_key,
) {

  if $_facts2ca_s3_region == undef {
    $facts2ca_s3_region = 'us-east-1'
  } else {
    $facts2ca_s3_region = $_facts2ca_s3_region
  }

  package { 'gem::aws-sdk':
    name     => 'aws-sdk',
    ensure   => '2.0.33',
    provider => pe_gem,
  }

  file { 'facts2ca::config':
    path    => '/etc/puppetlabs/mcollective/facts2ca.yaml',
    owner   => 'root',
    group   => 'root',
    mode    => '0640',
    backup  => false,
    content => template('cloudaware/facts2ca.yaml.erb'),
  }

  file { 'facts2ca::application':
    path   => '/opt/puppetlabs/mcollective/plugins/mcollective/application/facts2ca.rb',
    owner  => 'root',
    group  => 'root',
    mode   => '0644',
    backup => false,
    source => 'puppet:///modules/cloudaware/mcollective/facts2ca.rb',
  }

  file { 'facts2ca::cronjob':
    path    => '/etc/cron.d/facts2ca',
    ensure  => present,
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
    backup  => false,
    source  => 'puppet:///modules/cloudaware/cron.d/facts2ca',
    require => File[
      'facts2ca::config',
      'facts2ca::application'
    ],
    notify => Exec['facts2ca::run'],
  }

  exec { 'facts2ca::run':
    command     => 'mco facts2ca -c /var/lib/peadmin/.mcollective',
    path        => '/usr/local/bin:/bin',
    logoutput   => 'on_failure',
    refreshonly => true,
    require     => File['facts2ca::cronjob'],
  }

}
