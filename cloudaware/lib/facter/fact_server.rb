begin
  require 'facter/util/puppet_settings'
rescue LoadError => e
  rb_file = File.join(File.dirname(__FILE__), 'util', 'puppet_settings.rb')
  load rb_file if File.exists?(rb_file) or raise e
end

Facter.add(:fact_server) do
  setcode do
    Facter::Util::PuppetSettings.with_puppet do
      Puppet[:server]
    end
  end
end
