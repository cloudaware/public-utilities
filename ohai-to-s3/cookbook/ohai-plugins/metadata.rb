maintainer        "CloudAware"
maintainer_email  "vmartin@cloudaware.com"
license           "Private"
description       "Install custom ohai plugins."
long_description  IO.read(File.join(File.dirname(__FILE__), 'README.rdoc'))
version           "1.0.0"
recipe            "ohai-plugins", "Install custom ohai plugins."
name              "ohai-plugins"

%w{ubuntu}.each do |os|
  supports os
end
