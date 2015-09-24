#!/usr/bin/env ruby

require 'digest'
require 'logger'
require 'net/http'
require 'socket'
require 'yaml'

docker_log_files = ['/var/log/docker.log', '/var/log/upstart/docker.log']
output_log_file_path = '/var/log/ossec-docker-logs.log'
data_filename = '/tmp/ossec-docker-logs.yml'

def get_exec_details(line)
  id = line.match(/\/exec\/\S+\//).to_s.split('/').last

  unix_socket = UNIXSocket.new('/var/run/docker.sock')
  socket = Net::BufferedIO.new(unix_socket)
  request_string = "/exec/#{ id }/json"
  request = Net::HTTP::Get.new(request_string)
  request.exec(socket, '1.1', request_string)

  begin
    response = Net::HTTPResponse.read_new(socket)
  end while response.kind_of?(Net::HTTPContinue)
    response.reading_body(socket, request.response_body_permitted?) { }

  if response.code == '200'
    YAML.load(response.body).to_hash
  else
    nil
  end
end

exit 1 if `whoami`.chomp != 'root'

docker_log = docker_log_files.map { |file| file if File.exists?(file) }.compact.first
exit 0 unless docker_log

hostname = Socket.gethostname
output_log_file = File.new(output_log_file_path, 'a', 0600)
log = Logger.new(output_log_file, 1, 1048576)
log.level = Logger::INFO
log.formatter = proc do |severity, datetime, progname, msg|
  datetime_format = datetime.strftime("%b %d %H:%M:%S")
  "#{ datetime_format } #{ hostname } ossec-docker-logs: #{ msg }\n"
end

data = {}
if File.exists?(data_filename)
  data = YAML.load_file(data_filename)
end

docker_log_md5 = Digest::MD5.hexdigest(File.read(docker_log))

if data[docker_log]
  exit if data[docker_log][:md5] == docker_log_md5
else
  data[docker_log] = {}
end

data[docker_log][:md5] = docker_log_md5

docker_log_content = []
File.readlines(docker_log).each do |line|
  docker_log_content << line.rstrip
end

if data[docker_log][:last]
  last_index = docker_log_content.find_index(data[docker_log][:last])
  docker_log_content.slice!(0..last_index) if last_index
end

docker_log_content.each do |line|
  line.strip!
  case line
  when /info.+POST.+exec.+start/i
    details = get_exec_details(line)
    if details
      id = details['Container']['ID'].slice(0..11)
      command = details['ProcessConfig']['entrypoint'] + ' ' + details['ProcessConfig']['arguments'].join(' ')
      user = details['ProcessConfig']['user']
      privileged = details['ProcessConfig']['privileged']
      tty = details['ProcessConfig']['tty']

      log.info "#{ id } exec command='#{ command }' user='#{ user }' privileged='#{ privileged }' tty='#{ tty }'"
    end
  when /info.+POST.+(attach|stop|start)/i
    details = line.match(/\/containers\/\S+\/(attach|stop|start)/).to_s.split('/')
    id = details[2]
    id = id[0..11] unless id.match(/[g-zG-Z]/)
    action = details[3]

    log.info "#{ id } #{ action }"
  when /info.+POST.+containers.+create/i
    log.info "NULL create"
  when /info.+DELETE.+containers/i
    id = line.split('/').last

    log.info "#{ id } delete"
  end
end

data[docker_log][:last] = docker_log_content.last if docker_log_content.last

File.open(data_filename, 'w', 0600) do |f|
  f.write data.to_yaml
end
