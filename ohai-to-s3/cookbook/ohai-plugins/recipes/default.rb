ohai 'reload_ohai' do
  action :nothing
end

#Set config files.

if node['platform'] == 'windows'
 template "#{Ohai::Config[:plugin_path][0]}/windows_updates_count.rb" do
  source "windows_updates_count.rb.erb"
  notifies :reload, 'ohai[reload_ohai]', :immediately
 end
else
 template "#{Ohai::Config[:plugin_path][0]}/upgradable_packages.rb" do
  source "upgradable_packages.rb.erb"
  owner "root"
  group "root"
  mode "0755"
  notifies :reload, 'ohai[reload_ohai]', :immediately
 end
end
