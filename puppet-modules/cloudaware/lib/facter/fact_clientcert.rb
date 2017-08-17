Facter.add(:fact_clientcert) do
  confine :kernel => 'Linux'
  setcode do
    begin
      File.read('/etc/puppetlabs/puppet/puppet.conf').split("\n").each do |line|
        if line =~ /certname/
          @clientcert = line.split('=').last.strip
        end
      end
    rescue
      @clientcert = nil
    end
    @clientcert
  end
end

Facter.add(:fact_clientcert) do
  confine :kernel => 'windows'
  setcode do
    @clientcert = nil
    begin
      File.read('C:/ProgramData/PuppetLabs/puppet/etc/puppet.conf').split("\n").each do |line|
        if line =~ /certname/
          @clientcert = line.split('=').last.strip
        end
      end
    rescue
      @clientcert = nil
    end

    if @clientcert == nil
      @clientcert = Facter.value(:fqdn).downcase
    end
    @clientcert
  end
end
