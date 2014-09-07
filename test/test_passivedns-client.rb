unless Kernel.respond_to?(:require_relative)
	module Kernel
		def require_relative(path)
			require File.join(File.dirname(caller[0]), path.to_str)
		end
	end
end

require_relative 'helper'

class TestPassiveDnsQuery < Test::Unit::TestCase
	def test_instantiate_Nonexisting_Client
		assert_raise RuntimeError do
			PassiveDNS::Client.new(['doesnotexist'])
		end
	end

	def test_instantiate_All_Clients
		assert_nothing_raised do
			PassiveDNS::Client.new()
		end
	end
	
	def test_instantiate_Passive_DNS_State
		assert_not_nil(PassiveDNS::PDNSToolState.new)
	end
	
	def test_instantiate_Passive_DNS_State_database
		if File.exists?("test/test.sqlite3")
			File.unlink("test/test.sqlite3")
		end
		assert_not_nil(PassiveDNS::PDNSToolStateDB.new("test/test.sqlite3"))
		if File.exists?("test/test.sqlite3")
			File.unlink("test/test.sqlite3")
		end
	end
	
	def test_BFK
		assert_not_nil(PassiveDNS::BFK.new)
		assert_nothing_raised do
			PassiveDNS::Client.new(['bfk'])
		end
		rows = PassiveDNS::BFK.new.lookup("example.org")
		assert_not_nil(rows)
		assert_not_nil(rows.to_s)
		assert_not_nil(rows.to_xml)
		assert_not_nil(rows.to_json)
		assert_not_nil(rows.to_yaml)
		rows = PassiveDNS::BFK.new.lookup("example.org",3)
		assert_not_nil(rows)
		assert_not_nil(rows.to_s)
		assert_not_nil(rows.to_xml)
		assert_not_nil(rows.to_json)
		assert_not_nil(rows.to_yaml)
    assert_equal(3, rows.length)
	end
	
	def test_CERTEE
		assert_not_nil(PassiveDNS::CERTEE.new)
		assert_nothing_raised do
			PassiveDNS::Client.new(['certee'])
		end
		rows = PassiveDNS::CERTEE.new.lookup("sim.cert.ee")
		assert_not_nil(rows)
		assert_not_nil(rows.to_s)
		assert_not_nil(rows.to_xml)
		assert_not_nil(rows.to_json)
		assert_not_nil(rows.to_yaml)
		rows = PassiveDNS::CERTEE.new.lookup("sim.cert.ee",3)
		assert_not_nil(rows)
		assert_not_nil(rows.to_s)
		assert_not_nil(rows.to_xml)
		assert_not_nil(rows.to_json)
		assert_not_nil(rows.to_yaml)
    assert_equal(3, rows.length)
	end

	def test_DNSParse
		assert_not_nil(PassiveDNS::DNSParse.new)
		assert_nothing_raised do
			PassiveDNS::Client.new(['dnsparse'])
		end
		rows = PassiveDNS::DNSParse.new.lookup("example.org")
		assert_not_nil(rows)
		assert_not_nil(rows.to_s)
		assert_not_nil(rows.to_xml)
		assert_not_nil(rows.to_json)
		assert_not_nil(rows.to_yaml)
		rows = PassiveDNS::DNSParse.new.lookup("example.org",3)
		assert_not_nil(rows)
		assert_not_nil(rows.to_s)
		assert_not_nil(rows.to_xml)
		assert_not_nil(rows.to_json)
		assert_not_nil(rows.to_yaml)
    assert_equal(3, rows.length)
	end

	def test_DNSDB
		assert_not_nil(PassiveDNS::DNSDB.new)
		assert_nothing_raised do
			PassiveDNS::Client.new(['dnsdb'])
		end
		rows = PassiveDNS::DNSDB.new.lookup("example.org")
		assert_not_nil(rows)
		assert_not_nil(rows.to_s)
		assert_not_nil(rows.to_xml)
		assert_not_nil(rows.to_json)
		assert_not_nil(rows.to_yaml)
		rows = PassiveDNS::DNSDB.new.lookup("example.org",3)
		assert_not_nil(rows)
		assert_not_nil(rows.to_s)
		assert_not_nil(rows.to_xml)
		assert_not_nil(rows.to_json)
		assert_not_nil(rows.to_yaml)
    assert_equal(3, rows.length) # this will fail since DNSDB has an off by one error
	end

	def test_VirusTotal
		assert_not_nil(PassiveDNS::VirusTotal.new)
		assert_nothing_raised do
			PassiveDNS::Client.new(['virustotal'])
		end
		rows = PassiveDNS::VirusTotal.new.lookup("sim.cert.ee")
		assert_not_nil(rows)
		assert_not_nil(rows.to_s)
		assert_not_nil(rows.to_xml)
		assert_not_nil(rows.to_json)
		assert_not_nil(rows.to_yaml)
		rows = PassiveDNS::VirusTotal.new.lookup("google.com",3)
		assert_not_nil(rows)
		assert_not_nil(rows.to_s)
		assert_not_nil(rows.to_xml)
		assert_not_nil(rows.to_json)
		assert_not_nil(rows.to_yaml)
    assert_equal(3, rows.length)
	end
  
  def test_TCPIPUtils
    assert_not_nil(PassiveDNS::TCPIPUtils.new)
    assert_nothing_raised do
      PassiveDNS::Client.new(['tcpiputils'])
    end
    rows = PassiveDNS::TCPIPUtils.new.lookup("example.org")
    assert_not_nil(rows)
    assert_not_nil(rows.to_s)
    assert_not_nil(rows.to_xml)
    assert_not_nil(rows.to_json)
    assert_not_nil(rows.to_yaml)
    rows = PassiveDNS::TCPIPUtils.new.lookup("example.org",3)
    assert_not_nil(rows)
    assert_not_nil(rows.to_s)
    assert_not_nil(rows.to_xml)
    assert_not_nil(rows.to_json)
    assert_not_nil(rows.to_yaml)
    assert_equal(3, rows.length)
  end
end
