# probe.rb

require "cuba"
require "rack/protection"
require "json"
require "net/ping"
require "useragent"

include Net

Cuba.use Rack::Session::Cookie, :secret => "EckVagFiUjodphilImewatpatshUgAngyokQuekeirtenIdNiltUlWed"
Cuba.use Rack::Protection

def scan(ip, port, opts={})
  opts[:type]  ||= :simple
  opts[:proto] ||= :tcp
  return "not implemented" if opts[:proto].to_sym != :tcp
  return %x[nmap --reason -p #{port} #{ip} | egrep -o "open|closed|filtered"]
end

def ping(ip,opts={})
  opts[:count] ||= 1
  return %x[ping -A -c #{opts[:count]} -n -w 2 #{ip}].split("\n").last[/[0-9.]+/]
  #return %x[fping -C#{opts[:count]} -p100 -q #{ip} 2>&1 | cut -d: -f2].strip.split.inject(0.0) {|sum,v| sum + v.to_i } / opts[:count]
end

def cli?(user_agent)
	return true if UserAgent.parse(user_agent).browser =~ /(wget)|(curl)/i
  return false
end

def pre_wrap(string)
  return "<pre>#{string}</pre>" 
end

Cuba.define do
  on get do
    on "" do
      results = 'try "/ping" or "/scan/80", see https://github.com/anapsix/probe.im'
      res.write cli?(req.user_agent) ? results + "\n" : pre_wrap(results)
    end
    on "scan/:port" do |port|
      results = scan(req.ip, port).to_s
      res.write cli?(req.user_agent) ? results + "\n" : pre_wrap(results)
    end
    on "scan/:port/:proto" do |port,proto|
      results = scan(req.ip, port, :proto => proto).to_s
      res.write cli?(req.user_agent) ? results + "\n" : pre_wrap(results)
    end
    on "ping" do
      results = ping(req.ip).to_s
      q = env['QUERY_STRING'].split('=')
      j = Hash[*q]['json'] || 'no'
      if j.nil? || j == '0' || j == 'no' || j == 'false'
        res.write cli?(req.user_agent) ? results + "\n" : pre_wrap(results)
      else
        res.write cli?(req.user_agent) ? { "ping" => results }.to_json + "\n" : pre_wrap({ "ping" => results }.to_json)
      end
    end
  end
end
