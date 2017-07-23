Facter.add(:fact_server) do
  confine :kernel => 'Linux'
  setcode do
    begin
      File.read('/etc/puppetlabs/puppet/puppet.conf').split("\n").each do |line|
        if line =~ /server/
          @server = line.split('=').last.strip
        end
      end
    rescue
      @server = nil
    end
    @server
  end
end

Facter.add(:fact_server) do
  confine :kernel => 'windows'
  setcode do
    begin
      File.read('C:/ProgramData/PuppetLabs/puppet/etc/puppet.conf').split("\n").each do |line|
        if line =~ /server/
          @server = line.split('=').last.strip
        end
      end
    rescue
      @server = nil
    end
    @server
  end
end
