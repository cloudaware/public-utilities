require 'aws-sdk'
require 'json'
require 'logger'
require 'yaml'

class MCollective::Application::Facts2ca < MCollective::Application
  description 'Tool for upload facts to CloudAware'

  def find_nodes
    client = MCollective::Client.new(options[:config])
    client.options = options

    nodes = []
    client.req('ping', 'discovery') do |resp|
      nodes << resp[:senderid]
    end

    @log.info "Nodes: #{nodes.size}"
    nodes
  end

  def get_facts(node)
    util = rpcclient('rpcutil')
    util.identity_filter node
    util.progress = false

    inventory = util.custom_request('inventory', {}, node, 'identity' => node).first

    if inventory[:statuscode].zero?
      @log.info "Node: #{node}, facts: #{inventory[:data][:facts].size}"
      inventory[:data][:facts].empty? ? nil : inventory[:data][:facts]
    else
      @log.error "Failed to retrieve facts for #{node}: #{inventory[:statusmsg]}"
      return nil
    end
  end

  def load_yaml_config(path)
    config = YAML.load_file(path)
    raise "Can't find s3_bucket parameter value" unless config['s3_bucket']

    config
  rescue => e
    @log.error "Failed to load config file #{path}. Message: #{e.message}"
    exit 1
  end

  def main
    @log = Logger.new('/var/log/puppetlabs/facts2ca.log')
    @log.level = Logger::INFO

    lock_file = '/tmp/facts2ca.lock'
    unless File.new(lock_file, 'w').flock(File::LOCK_NB | File::LOCK_EX)
      @log.warn "File #{lock_file} is locked by another process. Exit"
      exit 1
    end

    config = load_yaml_config('/etc/puppetlabs/mcollective/facts2ca.yaml')

    data = []
    find_nodes.each do |node|
      data << get_facts(node)
    end

    options = {}
    options[:region] = config['s3_region'] if config['s3_region']
    options[:access_key_id] = config['access_key'] if config['access_key']
    options[:secret_access_key] = config['secret_key'] if config['secret_key']

    begin
      s3 = Aws::S3::Client.new(options)
      data.compact.each do |node_data|
        key = node_data['ec2_metadata']['instance-id']
        next unless key
        resp = s3.put_object(
          bucket: config['s3_bucket'].chomp('/'),
          key: "#{key}.json",
          body: node_data.to_json
        )
        @log.info "Facts of the instance #{key} uploaded" if resp.successful?
      end
    rescue => e
      @log.error "Failed to upload to S3. Message: #{e.message}"
    end
  end
end
