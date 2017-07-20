Puppet::Type.type(:package).provide :pe_gem, :parent => :gem do
  has_feature :versionable, :install_options

  commands :gemcmd => '/opt/puppet/bin/gem'
end
