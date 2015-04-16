# probe.rb

require "cuba"
require "rack/protection"
require "json"
#require "net/ping"
require "useragent"
require "securerandom"

#include Net

Cuba.use Rack::Session::Cookie, :secret => SecureRandom.base64(42)
Cuba.use Rack::Protection

def scan(ip, port, opts={})
  opts[:type]  ||= :simple
  opts[:proto] ||= :tcp
  return "not implemented" unless port.to_i > 0
  return "not implemented" if opts[:proto].to_sym != :tcp
  return %x[nmap -Pn --reason -p #{port} #{ip} | egrep -o "open|closed|filtered"].strip
end

def ping(ip,opts={})
  opts[:count] ||= 1
  #return %x[ping -A -c #{opts[:count]} -n -w 2 #{ip}].split("\n").last[/[0-9.]+/]
  return %x[fping -C#{opts[:count]} -p50 -q #{ip} 2>&1 | cut -d: -f2].strip.split.inject(0.0) {|sum,v| sum + v.to_i } / opts[:count]
end

def cli?(user_agent)
  return true if UserAgent.parse(user_agent).browser =~ /(wget)|(curl)/i
  return false
end

def pre_wrap(string)
  return "<pre>#{string}</pre>" 
end

def auto_wrap(results)
  return cli?(req.user_agent) ? results + "\n" : pre_wrap(results)
end

Cuba.define do
  on get do
    # /favicon.ico
    on "favicon.ico" do
      res.status = 404
      res.write "#### 404 ####"
      res.finish
    end
    on root do
      results = 'try "/ping[?json=1]" or "/scan/80", see https://github.com/anapsix/probe.im'
      res.write cli?(req.user_agent) ? results + "\n" : pre_wrap(results)
    end
    on "scan/:port/:proto" do |port,proto|
      results = scan(req.ip, port, :proto => proto).to_s.strip
      q = env['QUERY_STRING'][/=\S/] ? env['QUERY_STRING'].split('=') : [ "json", nil ]
      j = Hash[*q]['json'] || nil
      if j.nil? || j == '0' || j == 'no' || j == 'false'
        res.write auto_wrap(results)
      else
        res.write auto_wrap({ "scan/#{port}/#{proto}" => results }.to_json)
      end
    end
    on "scan/:port" do |port|
      results = scan(req.ip, port).to_s.strip
      q = env['QUERY_STRING'][/=\S/] ? env['QUERY_STRING'].split('=') : [ "json", nil ]
      j = Hash[*q]['json'] || nil
      if j.nil? || j == '0' || j == 'no' || j == 'false'
        res.write auto_wrap(results)
      else
        res.write auto_wrap({ "scan/#{port}" => results }.to_json)
      end
    end
    on "ping" do
      results = ping(req.ip).to_s
      q = env['QUERY_STRING'][/=\S/] ? env['QUERY_STRING'].split('=') : [ "json", nil ]
      j = Hash[*q]['json'] || nil
      if j.nil? || j == '0' || j == 'no' || j == 'false'
        res.write auto_wrap(results)
      else
        res.write auto_wrap({ "ping" => results }.to_json)
      end
    end
  end
end
