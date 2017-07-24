# Get upgradable packages count for Debian/RH systems

# Use yum
def get_pkg_yum()
  # yum with --security parameter reports number of updates available
  res_str = nil
  begin
    exec_out = IO.popen("yum --security check-update")
  rescue Exception => err
    Facter.debug("yum execution error \"#{err}\"")
    return
  end
  while (line = exec_out.gets) do
    res = line.chomp!.match(/(^\d+) package\(s\) needed for security, out of (\d+) available$/)
    res_str = res unless res.nil?
  end
  exec_out.close

  # Yum return exitcode 100 in case of updates available
  if (($?.exitstatus != 100) || (res_str.nil?))
    $count_upg = 0
    $count_sec = 0
  else
    begin
      $count_upg = res_str[2].to_i
      $count_sec = res_str[1].to_i
    rescue Exception => err
      Facter.debug("yum output parse error \"#{err}\"")
      $count_upg = 0
      $count_sec = 0
    end
  end
end

# Use apt-get
def get_pkg_apt()
  # Using apt-check (python), only Ubuntu (with security packages separation)
  begin
    exec_out = IO.popen("/usr/lib/update-notifier/apt-check --human-readable")
  rescue Exception => err
    Facter.debug("apt-check execution error \"#{err}\"")
    return 0
  end

  exec_out.each do |line|
    if (/packages can be updated/i =~ line)
      $count_upg = line.match(/^\d+/)[0].to_i
    end
    if (/updates are security updates/i =~ line)
      $count_sec = line.match(/^\d+/)[0].to_i
    end
  end
end

# Counters
$count_upg = 0
$count_sec = 0

# Get values
case Facter.value(:osfamily)
  when "RedHat"
    get_pkg_yum
  when "Debian"
    get_pkg_apt
end

# Sometimes Amazon linux not detected as "RedHat"
get_pkg_yum if ((Facter.value(:osfamily) == "Linux") && (Facter.value(:operatingsystem) == "Amazon"))

# The facts
Facter.add("upgradable_packages")          { setcode { $count_upg.to_s } }
Facter.add("upgradable_security_packages") { setcode { $count_sec.to_s } }
