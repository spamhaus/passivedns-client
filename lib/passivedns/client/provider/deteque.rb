# DESCRIPTION: this is a module to query the Deteque passive DNS database
# to request an API key, please go to https://pdns.deteque.com/ and register

#
# Notice to users: this module uses a very limited portion of the Deteque API
# In fact, the Deteque API allows for a much broader flexibility.
# * It can perform, for example, searches on specific labels (not only domain names),
#   so you can search for "paypal" and try to find phishing domain names
# * It would allow to search for phishing patterns (fuzzy search); for example, looking for
#   'bankofamerica.com', it would return similar domain names, typosquatted domains and domains 
#    that look shady.
# Unfortunalu, the passivedns library doesn't provide an interface that would allow to
# plug in this kind fof operations.
#

require 'net/http'
require 'net/https'
require 'configparser'
require 'json'

module PassiveDNS #:nodoc: don't document this
    # The Provider module contains all the Passive DNS provider client code
    module Provider
        # Queries Deteque passive DNS database
        class Deteque < PassiveDB
            # Sets the modules self-reported name to "DETEQUE"
            def self.name
                "Deteque"
            end

            # Sets the configuration section name to "deteque"
            def self.config_section_name
                "deteque"
            end

            # Sets the command line database argument to "d"
            def self.option_letter
                "q"
            end

            # :debug enables verbose logging to standard output
             attr_accessor :debug
            # === Options
            # * :debug       Sets the debug flag for the module
            # * "USERNAME"   REQUIRED: The USERNAME associated with Deteque pDNS
            # * "PASSWORD"   REQUIRED: The PASSWORD associated with Deteque pDNS
            # * "AUTHFILE"   REQUIRED: The path to the file that contains the cache to the auth token
            #
            # === Example Instantiation
            #
            #   options = {
            #     :debug => true,
            #     "USERNAME" => "foo@example.com",
            #     "PASSWORD" => "changeme"
            #     "AUTHFILE" => "/root/.deteque.token"
            #   }
            #
            #   PassiveDNS::Provider::Deteque.new(options)
            #
            def initialize(options={})
                @debug    = options[:debug]     || false
                @timeout  = options[:timeout]   || 20
                @user     = options["USERNAME"] || raise("USERNAME option required for #{self.class}")
                @pass     = options["PASSWORD"] || raise("PASSWORD option required for #{self.class}")
                @authfile = options["AUTHFILE"] || "#{ENV['HOME']}/.deteque-pdns.token"
                @base     = options["URL"]      || "https://api.pdns.deteque.com/v2"
            end

            # Takes a label (either a domain or an IP address) and returns
            # an array of PassiveDNS::PDNSResult instances with the answers to the query
            def lookup(label, limit=1000)
                $stderr.puts "DEBUG: #{self.class.name}.lookup(#{label})" if @debug

                token = getAuthToken()
                $stderr.puts "TOKEN IS: #{token}" if @debug

                Timeout::timeout(@timeout) {
                    url = nil
                    if label =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\/\d{1,2})?$/
                        url = "#{@base}/_search/rdata/#{label}?stype=em"
                    else
                        url = "#{@base}/_search/rrset/#{label}?stype=rm"
                    end

                    urlp = URI.parse url
                    http = Net::HTTP.new(urlp.host, urlp.port)
                    http.use_ssl = (urlp.scheme == 'https')
                    http.verify_mode = OpenSSL::SSL::VERIFY_NONE
                    http.verify_depth = 5
                    path = url
                    if limit
                        path << "&limit=#{limit}"
                    end

                    after = Date.today.prev_year.to_time.to_i
                    path << "&last_seen_gt=#{after}"

                    request = Net::HTTP::Get.new(path)
                    request.add_field("User-Agent", "Ruby/#{RUBY_VERSION} passivedns-client rubygem v#{PassiveDNS::Client::VERSION}")
                    request.add_field("Accept", "application/json")
                    request.add_field("Authorization", token)
                    t1 = Time.now
                    response = http.request(request)
                    t2 = Time.now
                    $stderr.puts response.body if @debug
                    ret = parse_json(response.body, t2 - t1)
                    ret
                }
            rescue Timeout::Error => e
                $stderr.puts "#{self.class.name} lookup timed out: #{label}"
            end

        private

            # parses the response of Deteque pDNS's JSON reply to generate an array of PDNSResult
            def parse_json(page, response_time)
                res = []
                raise "Error: unable to parse request" if page =~ /Error: unable to parse request/
                #$stdout.puts page

                data = JSON.parse(page)
                records = data['records']

                records.each do |record|
                    answer    = record['rdata']
                    query     = record['rname']
                    rrtype    = record['rtype']

                    if record['first_seen']
                        firstseen = Time.at(record['first_seen'].to_i)
                    end

                    if record['last_seen']
                        lastseen  = Time.at(record['last_seen'].to_i)
                    end

                    res << PDNSResult.new(self.class.name,response_time,query,answer,rrtype,0,firstseen,lastseen,0)
                end # end each
                res
            rescue Exception => e
                $stderr.puts "#{self.class.name} Exception: #{e}"
                $stderr.puts page
                raise e
            end

            def getAuthToken()
                now = Date.today.to_time.to_i

                if File.exist?(@authfile)
                    $stderr.puts "AUTHFILE found" if @debug

                    cp = ConfigParser.new(@authfile)
                    expires = cp["EXPIRES"].to_i
                    token = cp["TOKEN"]

                    if now < expires
                        $stderr.puts "TOKEN IS VALID" if @debug
                        return token
                    end
                        $stderr.puts "TOKEN IS NOT VALID" if @debug
                else
                    $stderr.puts "AUTHFILE NOT found" if @debug
                end

                # Renew the TOKEN
                Timeout::timeout(@timeout) {
                    url = "#{@base}/login"
                    body = {'username' => @user, 'password' => @pass}.to_json

                    urlp = URI.parse url
                    http = Net::HTTP.new(urlp.host, urlp.port)
                    http.use_ssl = (urlp.scheme == 'https')
                    http.verify_mode = OpenSSL::SSL::VERIFY_NONE
                    http.verify_depth = 5
                    path = url

                    request = Net::HTTP::Post.new(path, 'Content-Type' => 'application/json')
                    request.body = body
                    request.add_field("User-Agent", "Ruby/#{RUBY_VERSION} passivedns-client rubygem v#{PassiveDNS::Client::VERSION}")
                    request.add_field("Accept", "application/json")
                    response = http.request(request)
                    #$stderr.puts response.code if @debug
                    #$stderr.puts response.body if @debug

                    if response.code.to_i != 200
                        raise "#{self.class.name} Authentication failed"
                    end

                    data = JSON.parse(response.body)
                    token = "Bearer "
                    token << data["token"]
                    expires = data["expires"].to_i

                    content = ""
                    content << "TOKEN = #{token}\n"
                    content << "EXPIRES = #{expires}\n"

                    File.open(@authfile, "w") do |f|
                        f.write(content)
                    end

                    token
                }
            rescue Exception => e
                $stderr.puts "#{self.class.name} Exception: #{e}"
                $stderr.puts page
                raise e
            end

        end #class
    end #module
end #module
