# Determine the number of the pending Windows updates
#   windows_updates_optional - number of the optional updates available
#   windows_updates_important - number of the important updates available

def get_win_updates()
  session = WIN32OLE.new("Microsoft.Update.Session")
  searcher = session.CreateUpdateSearcher
  query = "IsInstalled=0 and Type='Software'"
  search_result = searcher.search(query)
  result = []

  if search_result.updates.count > 0
    search_result.updates.each do |update|
      regexp = /(?<name>.*\((?<version>\S+)\))/
      matches = regexp.match(update.Title)
      if matches
        h = Hash.new
        h['name'] = matches[:name]
        h['version'] = matches[:version]
        h['security'] = true if matches[:name] =~ /security/i
        h['auto'] = true if update.AutoSelectOnWebSites
        result << h
      end
    end
  end

  {
    'total'     => result.size,
    'security'  => result.map { |h| h if h['security'] }.compact.size,
    'important' => result.map { |h| h if h['auto']     }.compact.size,
    'optional'  => result.map { |h| h unless h['auto'] }.compact.size,
    'list'      => result
  }
end

if (Facter.value(:kernel) == "windows")
  require 'win32ole'
  require 'tmpdir'

  cache_file     = "#{ Dir::tmpdir }/package_updates_cache.dat"
  cache_interval = 60*60*24 # seconds

  result = Hash[
    'total'     => -1,
    'security'  => -1,
    'important' => -1,
    'optional'  => -1,
    'list'      => [],
    'date'      =>  0
  ]

  if (File.exist?(cache_file))
    begin
      result = Marshal.load(File.binread(cache_file))
    rescue
#      result = Hash.new
      result = Hash[
        'total'     => -1,
        'security'  => -1,
        'important' => -1,
        'optional'  => -1,
        'list'      => [],
        'date'      =>  0
      ]
    end
  end

  if ((Time.now - result['date']).to_i > cache_interval)
    result = get_win_updates()
    result['date'] = Time.now
    File.open(cache_file, 'w') { |f| f.write(Marshal.dump(result)) }
  end

  Facter.add("windows_updates_optional" ) { setcode { result['optional']  } }
  Facter.add("windows_updates_important") { setcode { result['important'] } }
end
