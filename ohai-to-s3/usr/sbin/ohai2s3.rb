#!/usr/bin/env ruby

require 'rubygems'
require 'aws-sdk'
require 'json'
require 'logger'

@nodes={}
@aws_key=""
@aws_secret=""
@aws_bucket=""
@aws_region="us-east-1"
@logfile="/var/log/ohai2s3.log"

@log = Logger.new(@logfile, 'weekly')
@log.level = Logger::INFO

def get_nodes()
 @log.info "Getting list of ohai items for each node"
 begin
  nodes_list=`knife node list`
  nodes_list.split("\n").each do |node|
   @nodes[node.gsub(/\n/,"")]=JSON.parse(`knife node show -l #{node.gsub(/\n/,"")} -F json`)
  end
 rescue => e
  @log.error "Failed to get ohai items for nodes due to error: #{ e.message }"
 end
end

def put2s3()
 begin
  options = Hash.new
  options[:region] = @aws_region if @aws_region
  options[:access_key_id] = @aws_key if @aws_key
  options[:secret_access_key] = @aws_secret if @aws_secret
  s3 = Aws::S3::Client.new(options)
  @nodes.each_key do |node_key|
   key = @nodes[node_key]["automatic"]["ec2"]["instance_id"]
   if key
    resp = s3.put_object(:bucket => @aws_bucket.chomp('/'), :key => "#{key}.json", :body => @nodes[node_key].to_s)
    @log.info "Facts for instance #{ key } uploaded successfully" if resp.successful?
   end
  end
 rescue => e
  @log.error "Failed to upload to S3 due to error: #{ e.message }"
 end
end

get_nodes()
put2s3()
